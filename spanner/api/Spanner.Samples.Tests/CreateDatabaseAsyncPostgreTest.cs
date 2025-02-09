﻿// Copyright 2022 Google Inc.
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

using Google.Cloud.Spanner.Admin.Database.V1;
using System;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

[Collection(nameof(SpannerFixture))]
public class CreateDatabaseAsyncPostgreTest
{
    private readonly SpannerFixture _spannerFixture;

    private readonly CreateDatabaseAsyncPostgreSample _sample;

    public CreateDatabaseAsyncPostgreTest(SpannerFixture spannerFixture)
    {
        _spannerFixture = spannerFixture;
        _sample = new CreateDatabaseAsyncPostgreSample();
    }

    [Fact]
    public async Task TestCreateDatabaseAsyncPostgre()
    {
        // Arrange.
        var databaseId = $"my-db-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";

        // Act.
        await _sample.CreateDatabaseAsyncPostgre(_spannerFixture.ProjectId, _spannerFixture.InstanceId, databaseId);

        // Assert.
        var databases = _spannerFixture.GetDatabases();
        Assert.Contains(databases, d => d.DatabaseName.DatabaseId == databaseId && d.DatabaseDialect == DatabaseDialect.Postgresql);
    }
}
