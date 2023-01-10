﻿// Copyright 2023 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// [START spanner_enable_fine_grained_access]

using Google.Api.Gax;
using Google.Cloud.Iam.V1;
using Google.Cloud.Spanner.Admin.Database.V1;

public class EnableFineGrainedAccessSample
{
    public Policy EnableFineGrainedAccess(string projectId, string instanceId, string databaseId, string databaseRole, string iamMember)
    {
        var resourceName = new UnparsedResourceName($"projects/{projectId}/instances/{instanceId}/databases/{databaseId}");

        var client = new DatabaseAdminClientBuilder().Build();

        // Requests policy version 3. As earlier versions does not support condition field in role binding.
        // For more info see https://cloud.google.com/iam/docs/policies#versions.
        GetIamPolicyRequest getIamPolicyRequest = new GetIamPolicyRequest
        {
            ResourceAsResourceName = resourceName,
            Options = new GetPolicyOptions
            {
                RequestedPolicyVersion = 3
            }
        };

        var policy = client.GetIamPolicy(getIamPolicyRequest);

        Binding newBinding = new Binding
        {
            Role = "roles/spanner.fineGrainedAccessUser",
            Members = { iamMember },
            Condition = new Google.Type.Expr
            {
                Title = "DatabaseRoleBindingTitle",
                Expression = $"resource.name.endsWith('/databaseRoles/{databaseRole}')"
            }
        };

        policy.Bindings.Add(newBinding);
        if (policy.Version < 3)
        {
            policy.Version = 3;
        }
        SetIamPolicyRequest setIamPolicyRequest = new SetIamPolicyRequest
        {
            Policy = policy,
            ResourceAsResourceName = resourceName,
        };
        client.SetIamPolicy(setIamPolicyRequest);
        return policy;
    }
}
// [END spanner_enable_fine_grained_access]