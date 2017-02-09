// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

// Warning: This code was generated by a tool.
// 
// Changes to this file may cause incorrect behavior and will be lost if the
// code is regenerated.

using System;
using System.Collections.Generic;
using System.Linq;
using Hyak.Common;
using Microsoft.Azure.Management.Automation.Models;

namespace Microsoft.Azure.Management.Automation.Models
{
    /// <summary>
    /// The response model for the list job operation.
    /// </summary>
    public partial class DscCompilationJobListResponse : OperationResponseWithSkipToken
    {
        private IList<DscCompilationJob> _dscCompilationJobs;
        
        /// <summary>
        /// Optional. Gets or sets a list of Dsc Compilation jobs.
        /// </summary>
        public IList<DscCompilationJob> DscCompilationJobs
        {
            get { return this._dscCompilationJobs; }
            set { this._dscCompilationJobs = value; }
        }
        
        /// <summary>
        /// Initializes a new instance of the DscCompilationJobListResponse
        /// class.
        /// </summary>
        public DscCompilationJobListResponse()
        {
            this.DscCompilationJobs = new LazyList<DscCompilationJob>();
        }
    }
}
