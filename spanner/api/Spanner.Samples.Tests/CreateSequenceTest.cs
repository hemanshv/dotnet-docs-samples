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

using System.Threading.Tasks;
using Xunit;

[Collection(nameof(SpannerFixture))]
public class CreateSequenceTest
{
    private readonly SpannerFixture _spannerFixture;

    public CreateSequenceTest(SpannerFixture spannerFixture)
    {
        _spannerFixture = spannerFixture;
    }

    [Fact]
    public async Task TestCreateSequenceAsync()
    {
        var databaseId = SpannerFixture.GenerateId("my-db-");
        await _spannerFixture.RunWithTemporaryDatabaseAsync(_spannerFixture.InstanceId, databaseId, async databaseId =>
        {
            var sample = new CreateSequenceSample();
            await sample.CreateSequenceAsync(_spannerFixture.ProjectId, _spannerFixture.InstanceId, databaseId);

            var getDatabaseDdlSample = new GetDatabaseDdlAsyncSample();
            var databaseDdlResponse = await getDatabaseDdlSample.GetDatabaseDdlAsync(_spannerFixture.ProjectId, _spannerFixture.InstanceId, databaseId);

            Assert.Collection(databaseDdlResponse.Statements,
                // Only check the start of the statement, as there is no guarantee on exactly
                // how Cloud Spanner will format the returned SQL string.
                statement => Assert.StartsWith("CREATE SEQUENCE Seq", statement),
                statement => Assert.StartsWith("CREATE TABLE Customers", statement)
            );
        });
    }
}
