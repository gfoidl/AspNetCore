// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

namespace RepoTasks
{
    public class CreateFrameworkListFile : Task
    {
        /// <summary>
        /// Files to extract basic information from and include in the list.
        /// </summary>
        [Required]
        public ITaskItem[] Files { get; set; }

        [Required]
        public string TargetFile { get; set; }

        /// <summary>
        /// Extra attributes to place on the root node.
        ///
        /// %(Identity): Attribute name.
        /// %(Value): Attribute value.
        /// </summary>
        public ITaskItem[] RootAttributes { get; set; }

        public override bool Execute()
        {
            XAttribute[] rootAttributes = RootAttributes
                ?.Select(item => new XAttribute(item.ItemSpec, item.GetMetadata("Value")))
                .ToArray();

            var frameworkManifest = new XElement("FileList", rootAttributes);

            var usedFileProfiles = new HashSet<string>();

            foreach (var f in Files
                .Select(item => new
                {
                    Item = item,
                    Filename = Path.GetFileName(item.ItemSpec),
                    AssemblyName = FileUtilities.GetAssemblyName(item.ItemSpec),
                    FileVersion = FileUtilities.GetFileVersion(item.ItemSpec),
                    IsNative = item.GetMetadata("IsNativeImage") == "true",
                    IsSymbolFile = item.GetMetadata("IsSymbolFile") == "true",
                    PackagePath = item.GetMetadata("PackagePath")
                })
                .Where(f =>
                    !f.IsSymbolFile &&
                    (f.Filename.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || f.IsNative))
                .OrderBy(f => f.Filename, StringComparer.Ordinal))
            {
                string path = Path.Combine(f.PackagePath, f.Filename).Replace('\\', '/');
                string type = f.IsNative ? "Native" : "Managed";
                var element = new XElement("File", new XAttribute("Path", path));

                if (path.StartsWith("analyzers/", StringComparison.Ordinal))
                {
                    type = "Analyzer";

                    if (path.EndsWith(".resources.dll", StringComparison.Ordinal))
                    {
                        // omit analyzer resources
                        continue;
                    }

                    var pathParts = path.Split('/');

                    if (pathParts.Length < 3 || !pathParts[1].Equals("dotnet", StringComparison.Ordinal) || pathParts.Length > 4)
                    {
                        Log.LogError($"Unexpected analyzer path format {path}.  Expected  'analyzers/dotnet(/language)/analyzer.dll");
                    }

                    // Check if we have enough parts for language directory and include it
                    if (pathParts.Length > 3)
                    {
                        element.Add(new XAttribute("Language", pathParts[2]));
                    }
                }

                element.Add(new XAttribute("Type", type));

                if (f.AssemblyName != null)
                {
                    byte[] publicKeyToken = f.AssemblyName.GetPublicKeyToken();
                    string publicKeyTokenHex;

                    if (publicKeyToken != null)
                    {
                        publicKeyTokenHex = BitConverter.ToString(publicKeyToken)
                            .ToLowerInvariant()
                            .Replace("-", "");
                    }
                    else
                    {
                        Log.LogError($"No public key token found for assembly {f.Item.ItemSpec}");
                        publicKeyTokenHex = "";
                    }

                    element.Add(
                        new XAttribute("AssemblyName", f.AssemblyName.Name),
                        new XAttribute("PublicKeyToken", publicKeyTokenHex),
                        new XAttribute("AssemblyVersion", f.AssemblyName.Version));
                }
                else if (!f.IsNative)
                {
                    // This file isn't managed and isn't native. Leave it off the list.
                    continue;
                }

                element.Add(new XAttribute("FileVersion", f.FileVersion));

                frameworkManifest.Add(element);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(TargetFile));
            File.WriteAllText(TargetFile, frameworkManifest.ToString());

            return !Log.HasLoggedErrors;
        }
    }
}
