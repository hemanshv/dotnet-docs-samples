﻿// Copyright 2020 Google Inc.
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

using System;
using System.Threading.Tasks;
using Xunit;

[Collection(nameof(SpannerFixture))]
public class ReadStaleDataAsyncTest
{
    private readonly SpannerFixture _spannerFixture;

    public ReadStaleDataAsyncTest(SpannerFixture spannerFixture)
    {
        _spannerFixture = spannerFixture;
    }

    [Fact]
    public async Task TestReadStaleDataAsync()
    {
        ReadStaleDataAsyncSample sample = new ReadStaleDataAsyncSample();
        await _spannerFixture.RefillMarketingBudgetsAsync(300000, 300000);

        // Add a delay of 15 seconds to ensure that the call to ReadStaleDataAsync reads the data updated by the previous statement. 
        // TODO: This is a workaround while issue https://b.corp.google.com/issues/265610770 is addressed.
        await Task.Delay(TimeSpan.FromSeconds(15));

        var albums = await sample.ReadStaleDataAsync(_spannerFixture.ProjectId, _spannerFixture.InstanceId, _spannerFixture.DatabaseId);
        Assert.Contains(albums, a => a.SingerId == 1 && a.AlbumId == 1 && a.MarketingBudget == 300000);
    }
}
