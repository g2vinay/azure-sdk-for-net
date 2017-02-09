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

namespace Microsoft.Azure.Management.Automation.Models
{
    public partial class ResourceCreateOrUpdateParameterBase
    {
        private string _location;
        
        /// <summary>
        /// Optional. Gets or sets the location of the resource.
        /// </summary>
        public string Location
        {
            get { return this._location; }
            set { this._location = value; }
        }
        
        private string _name;
        
        /// <summary>
        /// Optional. Gets or sets the name of the resource.
        /// </summary>
        public string Name
        {
            get { return this._name; }
            set { this._name = value; }
        }
        
        private IDictionary<string, string> _tags;
        
        /// <summary>
        /// Optional. Gets or sets the tags attached to the resource.
        /// </summary>
        public IDictionary<string, string> Tags
        {
            get { return this._tags; }
            set { this._tags = value; }
        }
        
        /// <summary>
        /// Initializes a new instance of the
        /// ResourceCreateOrUpdateParameterBase class.
        /// </summary>
        public ResourceCreateOrUpdateParameterBase()
        {
            this.Tags = new LazyDictionary<string, string>();
        }
    }
}
