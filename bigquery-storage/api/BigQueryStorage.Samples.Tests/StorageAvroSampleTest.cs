﻿/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Threading.Tasks;
using Xunit;

[Collection(nameof(BigQueryStorageFixture))]
public class StorageAvroSampleTest
{
    private readonly BigQueryStorageFixture _fixture;

    private readonly StorageAvroSample _sample;
    public StorageAvroSampleTest(BigQueryStorageFixture bigQueryStorageFixture)
    {
        _fixture = bigQueryStorageFixture;
        _sample = new StorageAvroSample();
    }

    [Fact]
    public async Task TestAvroSampleAsync()
    {
       var rows = await _sample.AvroSampleAsync(_fixture.ProjectId);
        Assert.NotEmpty(rows);
    }
}

