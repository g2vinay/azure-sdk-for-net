// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator 0.17.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.RecoveryServices.Backup
{
    using System.Threading.Tasks;
   using Microsoft.Rest.Azure;
   using Models;

    /// <summary>
    /// Extension methods for ItemLevelRecoveryConnectionsOperations.
    /// </summary>
    public static partial class ItemLevelRecoveryConnectionsOperationsExtensions
    {
            /// <summary>
            /// Revokes an iSCSI connection which can be used to download a script.
            /// Executing this script opens a file explorer displaying all recoverable
            /// files and folders. This is an asynchronous operation.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='vaultName'>
            /// The name of the recovery services vault.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group where the recovery services vault is
            /// present.
            /// </param>
            /// <param name='fabricName'>
            /// Fabric name associated with the backed up items.
            /// </param>
            /// <param name='containerName'>
            /// Container name associated with the backed up items.
            /// </param>
            /// <param name='protectedItemName'>
            /// Backed up item name whose files/folders are to be restored.
            /// </param>
            /// <param name='recoveryPointId'>
            /// Recovery point ID which represents backed up data. iSCSI connection will
            /// be revoked for this backed up data.
            /// </param>
            public static void Revoke(this IItemLevelRecoveryConnectionsOperations operations, string vaultName, string resourceGroupName, string fabricName, string containerName, string protectedItemName, string recoveryPointId)
            {
                System.Threading.Tasks.Task.Factory.StartNew(s => ((IItemLevelRecoveryConnectionsOperations)s).RevokeAsync(vaultName, resourceGroupName, fabricName, containerName, protectedItemName, recoveryPointId), operations, System.Threading.CancellationToken.None, System.Threading.Tasks.TaskCreationOptions.None,  System.Threading.Tasks.TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Revokes an iSCSI connection which can be used to download a script.
            /// Executing this script opens a file explorer displaying all recoverable
            /// files and folders. This is an asynchronous operation.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='vaultName'>
            /// The name of the recovery services vault.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group where the recovery services vault is
            /// present.
            /// </param>
            /// <param name='fabricName'>
            /// Fabric name associated with the backed up items.
            /// </param>
            /// <param name='containerName'>
            /// Container name associated with the backed up items.
            /// </param>
            /// <param name='protectedItemName'>
            /// Backed up item name whose files/folders are to be restored.
            /// </param>
            /// <param name='recoveryPointId'>
            /// Recovery point ID which represents backed up data. iSCSI connection will
            /// be revoked for this backed up data.
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async System.Threading.Tasks.Task RevokeAsync(this IItemLevelRecoveryConnectionsOperations operations, string vaultName, string resourceGroupName, string fabricName, string containerName, string protectedItemName, string recoveryPointId, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
            {
                await operations.RevokeWithHttpMessagesAsync(vaultName, resourceGroupName, fabricName, containerName, protectedItemName, recoveryPointId, null, cancellationToken).ConfigureAwait(false);
            }

            /// <summary>
            /// Provisions a script which invokes an iSCSI connection to the backup data.
            /// Executing this script opens a file explorer displaying all the
            /// recoverable files and folders. This is an asynchronous operation. To know
            /// the status of provisioning, call GetProtectedItemOperationResult API.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='vaultName'>
            /// The name of the recovery services vault.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group where the recovery services vault is
            /// present.
            /// </param>
            /// <param name='fabricName'>
            /// Fabric name associated with the backed up items.
            /// </param>
            /// <param name='containerName'>
            /// Container name associated with the backed up items.
            /// </param>
            /// <param name='protectedItemName'>
            /// Backed up item name whose files/folders are to be restored.
            /// </param>
            /// <param name='recoveryPointId'>
            /// Recovery point ID which represents backed up data. iSCSI connection will
            /// be provisioned for this backed up data.
            /// </param>
            /// <param name='resourceILRRequest'>
            /// resource ILR request
            /// </param>
            public static void Provision(this IItemLevelRecoveryConnectionsOperations operations, string vaultName, string resourceGroupName, string fabricName, string containerName, string protectedItemName, string recoveryPointId, ILRRequestResource resourceILRRequest)
            {
                System.Threading.Tasks.Task.Factory.StartNew(s => ((IItemLevelRecoveryConnectionsOperations)s).ProvisionAsync(vaultName, resourceGroupName, fabricName, containerName, protectedItemName, recoveryPointId, resourceILRRequest), operations, System.Threading.CancellationToken.None, System.Threading.Tasks.TaskCreationOptions.None,  System.Threading.Tasks.TaskScheduler.Default).Unwrap().GetAwaiter().GetResult();
            }

            /// <summary>
            /// Provisions a script which invokes an iSCSI connection to the backup data.
            /// Executing this script opens a file explorer displaying all the
            /// recoverable files and folders. This is an asynchronous operation. To know
            /// the status of provisioning, call GetProtectedItemOperationResult API.
            /// </summary>
            /// <param name='operations'>
            /// The operations group for this extension method.
            /// </param>
            /// <param name='vaultName'>
            /// The name of the recovery services vault.
            /// </param>
            /// <param name='resourceGroupName'>
            /// The name of the resource group where the recovery services vault is
            /// present.
            /// </param>
            /// <param name='fabricName'>
            /// Fabric name associated with the backed up items.
            /// </param>
            /// <param name='containerName'>
            /// Container name associated with the backed up items.
            /// </param>
            /// <param name='protectedItemName'>
            /// Backed up item name whose files/folders are to be restored.
            /// </param>
            /// <param name='recoveryPointId'>
            /// Recovery point ID which represents backed up data. iSCSI connection will
            /// be provisioned for this backed up data.
            /// </param>
            /// <param name='resourceILRRequest'>
            /// resource ILR request
            /// </param>
            /// <param name='cancellationToken'>
            /// The cancellation token.
            /// </param>
            public static async System.Threading.Tasks.Task ProvisionAsync(this IItemLevelRecoveryConnectionsOperations operations, string vaultName, string resourceGroupName, string fabricName, string containerName, string protectedItemName, string recoveryPointId, ILRRequestResource resourceILRRequest, System.Threading.CancellationToken cancellationToken = default(System.Threading.CancellationToken))
            {
                await operations.ProvisionWithHttpMessagesAsync(vaultName, resourceGroupName, fabricName, containerName, protectedItemName, recoveryPointId, resourceILRRequest, null, cancellationToken).ConfigureAwait(false);
            }

    }
}
