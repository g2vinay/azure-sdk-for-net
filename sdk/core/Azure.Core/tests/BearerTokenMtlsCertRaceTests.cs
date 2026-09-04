// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core.Pipeline;
using Azure.Core.TestFramework;
using Microsoft.AspNetCore.Http;
using NUnit.Framework;

namespace Azure.Core.Tests
{
    // Regression test for the mTLS Proof-of-Possession per-request certificate-affinity fix (#62546),
    // exercised end-to-end on the real code path (BearerTokenAuthenticationPolicy +
    // HttpClientTransport.Update + a real mTLS server):
    //
    //   Two requests are in flight on ONE pipeline/transport. Their access tokens are bound to
    //   DIFFERENT certificates (C1, C2) - as happens when the binding certificate rotates between
    //   two token acquisitions. The shared transport still holds only ONE "current" client
    //   certificate at a time (last-writer-wins: HttpClientTransport.Update swaps the shared
    //   HttpClient via Interlocked.Exchange). Without the fix, because the policy PINS the token at
    //   authorize time but the transport READS the certificate at send time, a concurrent swap would
    //   make request A egress its C1-bound token over C2, a cnf-enforcing resource would reject the
    //   mismatch with 401, and Azure.Core would NOT retry it (not a CAE challenge) - surfacing to the
    //   caller.
    //
    //   The fix makes the policy stamp each request's binding certificate onto the message, and the
    //   transport send each request over the client bound to THAT certificate. So even though A is
    //   released only after B rotated the shared transport to C2, A is still presented over C1 and
    //   succeeds (200). If this test fails with A == 401 / presented == C2, the affinity fix has
    //   regressed to the shared last-writer-wins behavior.
    [TestFixture]
    [NonParallelizable]
    public class BearerTokenMtlsCertRaceTests : PipelineTestBase
    {
        public BearerTokenMtlsCertRaceTests() : base(isAsync: true)
        {
        }

        [Test]
        public async Task ConcurrentRequests_EachTokenIsSentOverItsBoundCertificate()
        {
            X509Certificate2 c1 = GetCertificate(Pfx);
            X509Certificate2 c2 = GetCertificate(Pfx2);
            Assert.AreNotEqual(c1.Thumbprint, c2.Thumbprint, "Repro requires two distinct client certificates.");

            // The token string encodes the thumbprint of the cert it is bound to. The server performs
            // the resource-side cnf check: compare the TLS-presented client cert to the token's cert.
            string presentedForTokenC1 = null;
            var observations = new ConcurrentBag<(string TokenThumb, string PresentedThumb, bool Matched)>();

            using var server = new TestServer(async context =>
            {
                X509Certificate2 presented = context.Connection.ClientCertificate;
                string auth = context.Request.Headers["Authorization"].ToString(); // "PoP <thumbprint>"
                string tokenThumb = auth.Split(' ').LastOrDefault();
                string presentedThumb = presented?.Thumbprint;
                bool matched = presentedThumb != null &&
                               string.Equals(presentedThumb, tokenThumb, StringComparison.OrdinalIgnoreCase);

                observations.Add((tokenThumb, presentedThumb, matched));
                if (string.Equals(tokenThumb, c1.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    presentedForTokenC1 = presentedThumb;
                }

                context.Response.StatusCode = matched ? 200 : 401;
                await context.Response.WriteAsync(matched ? "ok" : $"cnf mismatch token={tokenThumb} presented={presentedThumb}");
            }, https: true);

            // Client trusts the dev server certificate. The bearer policy clones these options and adds
            // the binding cert on each Update, so the rebuilt client keeps trusting the server.
            var options = new HttpPipelineTransportOptions { ServerCertificateCustomValidationCallback = _ => true };

            // Options ctor => _clientFactory is a lambda (!= CreateDefaultClient) => Update() rebuilds
            // the shared HttpClient with the new cert. This is the updatable, single-slot transport.
            var transport = new HttpClientTransport(options);

            var credential = new RotatingCertCredential(c1, c2);
#pragma warning disable AZID0004 // Experimental transport-binding ctor
            var authPolicy = new UniqueScopeBearerPolicy(credential, "https://race.example/.default", options);
#pragma warning restore AZID0004
            var gate = new GatePolicy();

            // HttpPipeline wires authPolicy.TransportOptionsChanged -> transport.Update (the real path).
            var pipeline = new HttpPipeline(transport, new HttpPipelinePolicy[] { authPolicy, gate });

            // Request A: authorizes (token bound to C1, swaps transport to C1), then PARKS in the gate
            // BEFORE reaching the transport send.
            HttpMessage messageA = pipeline.CreateMessage();
            messageA.Request.Method = RequestMethod.Get;
            messageA.Request.Uri.Reset(server.Address);
            Task<Response> taskA = ExecuteRequest(messageA, pipeline);

            // Wait until A has parked; transport is now set to C1.
            await gate.Parked.Task;

            // Request B: authorizes (token bound to C2, swaps transport to C2) and sends. Its presented
            // cert matches its own token -> 200. Crucially it leaves the shared transport set to C2.
            HttpMessage messageB = pipeline.CreateMessage();
            messageB.Request.Method = RequestMethod.Get;
            messageB.Request.Uri.Reset(server.Address);
            Response respB = await ExecuteRequest(messageB, pipeline);

            // Release A: although the shared transport's current certificate is now C2, per-request
            // affinity routes A over the client bound to its OWN certificate (C1).
            gate.Release.SetResult(true);
            Response respA = await taskA;

            TestContext.WriteLine($"A: tokenBoundTo=C1({c1.Thumbprint}) presentedOnWire={presentedForTokenC1} status={respA.Status}");
            TestContext.WriteLine($"B: status={respB.Status}");
            foreach (var o in observations)
            {
                TestContext.WriteLine($"server saw token={o.TokenThumb} presented={o.PresentedThumb} matched={o.Matched}");
            }

            // B (token C2 over C2) succeeds.
            Assert.AreEqual(200, respB.Status, "Request B should match its own certificate.");

            // PROOF #1: with per-request certificate affinity, A's C1-bound token is presented over C1
            // even though B rotated the shared transport to C2 before A was released.
            Assert.AreEqual(c1.Thumbprint, presentedForTokenC1,
                "Request A's C1-bound token must egress over C1 (its own certificate), not the shared transport's current certificate.");

            // PROOF #2: because the presented certificate matched the token binding, the resource
            // returns 200 - no cnf-mismatch 401 surfaces to the caller.
            Assert.AreEqual(200, respA.Status,
                "With per-request certificate affinity (#62546), request A succeeds instead of failing with a cnf-mismatch 401.");
        }

        // Guards the ref-counting invariant behind per-request certificate affinity: a request that is
        // already in flight over its bound certificate (C1) must complete even if C1's cached client is
        // evicted from the bounded per-thumbprint cache WHILE the request is on the wire. The in-flight
        // send holds its OWN reference on the client wrapper, so eviction - which drops only the cache's
        // reference - must not dispose the HttpClient out from under the live request.
        [Test]
        public async Task InFlightRequest_SurvivesBoundClientEvictionMidSend()
        {
            X509Certificate2 c1 = GetCertificate(Pfx);

            var serverEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseServer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            string presentedThumb = null;

            using var server = new TestServer(async context =>
            {
                presentedThumb = context.Connection.ClientCertificate?.Thumbprint;
                serverEntered.TrySetResult(true);
                // Hold the request in flight: by now the client-side send has already acquired (and
                // referenced) C1's wrapper, so we can evict it from the cache underneath the live send.
                await releaseServer.Task;
                context.Response.StatusCode = 200;
                await context.Response.WriteAsync("ok");
            }, https: true);

            var options = new HttpPipelineTransportOptions { ServerCertificateCustomValidationCallback = _ => true };
            var transport = new HttpClientTransport(options);
            Assert.IsTrue(transport.IsRefCountingEnabled, "This transport must be reference-counted for the invariant under test to apply.");

            var credential = new RotatingCertCredential(c1, c1); // single acquisition -> always C1
#pragma warning disable AZID0004 // Experimental transport-binding ctor
            var authPolicy = new UniqueScopeBearerPolicy(credential, "https://evict.example/.default", options);
#pragma warning restore AZID0004
            var pipeline = new HttpPipeline(transport, new HttpPipelinePolicy[] { authPolicy });

            HttpMessage message = pipeline.CreateMessage();
            message.Request.Method = RequestMethod.Get;
            message.Request.Uri.Reset(server.Address);

            // A authorizes (indexes C1 in the cache), then sends over C1 and parks in the server handler.
            Task<Response> task = ExecuteRequest(message, pipeline);
            await serverEntered.Task;
            Assert.AreEqual(c1.Thumbprint, presentedThumb, "The in-flight request should present its bound certificate C1.");

            // Evict C1 by indexing more certificates than the cache holds (cap is 8) while A is on the
            // wire. Each Update drops the cache's reference on the oldest entry, and C1 is the oldest.
            var fillers = new List<X509Certificate2>();
            for (int i = 0; i < 16; i++)
            {
                X509Certificate2 filler = CreateEphemeralClientCertificate($"CN=evict-filler-{i}");
                fillers.Add(filler);
                var fillerOptions = new HttpPipelineTransportOptions { ServerCertificateCustomValidationCallback = _ => true };
                fillerOptions.ClientCertificates.Add(filler);
                transport.Update(fillerOptions);
            }

            // Release the parked request: its bound client was evicted from the cache, but the in-flight
            // send kept its own reference, so the HttpClient is still alive and the request completes 200.
            releaseServer.SetResult(true);
            Response response = await task;

            TestContext.WriteLine($"in-flight presented={presentedThumb} status={response.Status}");
            Assert.AreEqual(200, response.Status,
                "An in-flight request must survive eviction of its bound client from the cache mid-send (the send holds its own reference).");

            foreach (X509Certificate2 filler in fillers)
            {
                filler.Dispose();
            }
        }

        // Creates a throwaway self-signed client certificate used only to grow/evict the transport's
        // per-thumbprint client cache. It is never presented in a TLS handshake, so an ephemeral key is
        // sufficient; each certificate has a distinct thumbprint.
        private static X509Certificate2 CreateEphemeralClientCertificate(string subjectName)
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest(subjectName, key, HashAlgorithmName.SHA256);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }

        // Returns a token bound to C1 on the first acquisition and C2 afterwards, modelling a binding-cert
        // rotation between two token acquisitions. The token string is the bound cert's thumbprint so the
        // server can perform a cnf check.
        private sealed class RotatingCertCredential : TokenCredential
        {
            private readonly X509Certificate2 _c1;
            private readonly X509Certificate2 _c2;
            private int _calls;

            public RotatingCertCredential(X509Certificate2 c1, X509Certificate2 c2)
            {
                _c1 = c1;
                _c2 = c2;
            }

            private AccessToken Next()
            {
                X509Certificate2 cert = Interlocked.Increment(ref _calls) == 1 ? _c1 : _c2;
                return new AccessToken(cert.Thumbprint, DateTimeOffset.UtcNow.AddHours(1), null, "PoP", cert);
            }

            public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
                => Next();

            public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
                => new ValueTask<AccessToken>(Next());
        }

        // Uses a unique scope per request so every request is an AccessTokenCache miss and triggers a
        // fresh credential acquisition (defeats the cache's request coalescing deterministically). This
        // faithfully reproduces "a different binding cert per in-flight request", as happens during a
        // binding-cert rotation. All the real BearerTokenAuthenticationPolicy machinery still runs:
        // token pinned on the message at authorize, transport updated via UpdateTransportOptionsIfNeeded.
        private sealed class UniqueScopeBearerPolicy : BearerTokenAuthenticationPolicy
        {
            private int _n;

#pragma warning disable AZID0004
            public UniqueScopeBearerPolicy(TokenCredential credential, string scope, HttpPipelineTransportOptions options)
                : base(credential, scope, options)
            {
            }
#pragma warning restore AZID0004

            private TokenRequestContext NextContext(HttpMessage message)
                => new TokenRequestContext(
                    new[] { $"https://race.example/{Interlocked.Increment(ref _n)}/.default" },
                    message.Request.ClientRequestId);

            protected override ValueTask AuthorizeRequestAsync(HttpMessage message)
                => AuthenticateAndAuthorizeRequestAsync(message, NextContext(message));

            protected override void AuthorizeRequest(HttpMessage message)
                => AuthenticateAndAuthorizeRequest(message, NextContext(message));
        }

        // The first request to reach this policy parks until released; later requests pass straight
        // through. Because we send A, await Parked, then send B, A is deterministically the parked one.
        private sealed class GatePolicy : HttpPipelinePolicy
        {
            private int _count;

            public TaskCompletionSource<bool> Parked { get; } =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public TaskCompletionSource<bool> Release { get; } =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            public override async ValueTask ProcessAsync(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
            {
                if (Interlocked.Increment(ref _count) == 1)
                {
                    Parked.SetResult(true);
                    await Release.Task.ConfigureAwait(false);
                }
                await ProcessNextAsync(message, pipeline).ConfigureAwait(false);
            }

            public override void Process(HttpMessage message, ReadOnlyMemory<HttpPipelinePolicy> pipeline)
                => throw new NotSupportedException("This repro runs on the async path only.");
        }
    }
}
