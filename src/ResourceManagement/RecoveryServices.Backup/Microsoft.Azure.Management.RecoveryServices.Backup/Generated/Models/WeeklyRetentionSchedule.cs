// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator 0.17.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.Management.RecoveryServices.Backup.Models
{
    using System.Linq;

    /// <summary>
    /// Weekly retention schedule.
    /// </summary>
    public partial class WeeklyRetentionSchedule
    {
        /// <summary>
        /// Initializes a new instance of the WeeklyRetentionSchedule class.
        /// </summary>
        public WeeklyRetentionSchedule() { }

        /// <summary>
        /// Initializes a new instance of the WeeklyRetentionSchedule class.
        /// </summary>
        /// <param name="daysOfTheWeek">List of days of week for weekly
        /// retention policy.</param>
        /// <param name="retentionTimes">Retention times of retention
        /// policy.</param>
        /// <param name="retentionDuration">Retention duration of retention
        /// Policy.</param>
        public WeeklyRetentionSchedule(System.Collections.Generic.IList<DayOfWeek?> daysOfTheWeek = default(System.Collections.Generic.IList<DayOfWeek?>), System.Collections.Generic.IList<System.DateTime?> retentionTimes = default(System.Collections.Generic.IList<System.DateTime?>), RetentionDuration retentionDuration = default(RetentionDuration))
        {
            DaysOfTheWeek = daysOfTheWeek;
            RetentionTimes = retentionTimes;
            RetentionDuration = retentionDuration;
        }

        /// <summary>
        /// Gets or sets list of days of week for weekly retention policy.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "daysOfTheWeek")]
        public System.Collections.Generic.IList<DayOfWeek?> DaysOfTheWeek { get; set; }

        /// <summary>
        /// Gets or sets retention times of retention policy.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "retentionTimes")]
        public System.Collections.Generic.IList<System.DateTime?> RetentionTimes { get; set; }

        /// <summary>
        /// Gets or sets retention duration of retention Policy.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "retentionDuration")]
        public RetentionDuration RetentionDuration { get; set; }

    }
}
