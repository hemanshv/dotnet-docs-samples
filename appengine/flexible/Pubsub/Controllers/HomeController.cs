/*
 * Copyright (c) 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

using Google.Cloud.PubSub.V1;
using Google.Protobuf;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Google.Apis.Auth;
using Pubsub.ViewModels;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Collections.Concurrent;

namespace Pubsub.Controllers
{
    public class HomeController : Controller
    {
        readonly PubsubOptions _options;
        // Lock protects all the static members.
        static object s_lock = new object();
        // Keep the received messages in a list.
        static List<string> s_receivedMessages = new List<string>();
        // Keep a cache of already seen jwt tokens.
        private static readonly ConcurrentDictionary<string, bool> s_tokens = new ConcurrentDictionary<string, bool>();
        // Keep a cache of already seen claims.
        private static readonly ConcurrentDictionary<PubSubPayload, bool> s_claims = new ConcurrentDictionary<PubSubPayload, bool>();
        readonly PublisherClient _publisher;

        public HomeController(IOptions<PubsubOptions> options,
            PublisherClient publisher)
        {
            _options = options.Value;
            _publisher = publisher;
        }

        // [START gae_flex_pubsub_index]
        [HttpGet]
        [HttpPost]
        public IActionResult Index(MessageForm messageForm)
        {
            var model = new MessageList();
            if (!_options.HasGoodProjectId())
            {
                model.MissingProjectId = true;
                return View(model);
            }
            if (!string.IsNullOrEmpty(messageForm.Message))
            {
                // Publish the message.
                var pubsubMessage = new PubsubMessage()
                {
                    Data = ByteString.CopyFromUtf8(messageForm.Message)
                };
                pubsubMessage.Attributes["token"] = _options.VerificationToken;
                _publisher.PublishAsync(pubsubMessage);
                model.PublishedMessage = messageForm.Message;
            }
            // Render the current list of messages.
            lock (s_lock) model.Messages = s_receivedMessages.ToArray();
            return View(model);
        }
        // [END gae_flex_pubsub_index]

        // [START gae_flex_pubsub_push]
        /// <summary>
        /// Handle a push request coming from pubsub.
        /// </summary>
        [HttpPost]
        [Route("/Push")]
        public IActionResult Push([FromBody]PushBody body,
            [FromQuery]string token)
        {
            string verificationToken =
                token ?? body.message.attributes["token"];
            if (verificationToken != _options.VerificationToken)
            {
                return new BadRequestResult();
            }
            var messageBytes = Convert.FromBase64String(body.message.data);
            string message = System.Text.Encoding.UTF8.GetString(messageBytes);
            lock (s_lock) s_receivedMessages.Add(message);
            return new OkResult();
        }
        // [END gae_flex_pubsub_push]

        // [START gaeflex_net_pubsub_auth_push]
        /// <summary>
        /// Handle authenticated push request coming from pubsub.
        /// </summary>
        [HttpPost]
        [Route("/AuthPush")]
        public async Task<IActionResult> AuthPushAsync([FromBody] PushBody body, [FromQuery] string token)
        {
            string bearerToken = HttpContext.Request.Headers["Authorization"];
            string authToken = bearerToken.Split(" ")[1];
            s_tokens[authToken] = true;
    
            // Verify and decode the JWT.
            // Note: For high volume push requests, it would save some network
            // overhead if you verify the tokens offline by decoding them using
            // Google's Public Cert; caching already seen tokens works best when
            // a large volume of messages have prompted a single push server to
            // handle them, in which case they would all share the same token for
            // a limited time window.
            var claim = await JsonWebSignature.VerifySignedTokenAsync<PubSubPayload>(authToken);

            // IMPORTANT: you should validate claim details not covered
            // by signature and audience verification above, including:
            //   - Ensure that `claim.email` is equal to the expected service
            //     account set up in the push subscription settings.
            //   - Ensure that `claim.email_verified` is set to true.
            s_claims[claim] = true;

            string verificationToken = token ?? body.message.attributes["token"];
            if (verificationToken != _options.VerificationToken)
            {
                return new BadRequestResult();
            }
            var messageBytes = Convert.FromBase64String(body.message.data);
            string message = System.Text.Encoding.UTF8.GetString(messageBytes);
            lock (s_lock) s_receivedMessages.Add(message);
            return new OkResult();
        }
        // [END gaeflex_net_pubsub_auth_push]

        public IActionResult Error()
        {
            return View();
        }
    }

    /// <summary>
    /// Pubsub messages will arrive in this format.
    /// </summary>
    public class PushBody
    {
        public PushMessage message { get; set; }
        public string subscription { get; set; }
    }

    public class PushMessage
    {
        public Dictionary<string, string> attributes { get; set; }
        public string data { get; set; }
        public string message_id { get; set; }
        public string publish_time { get; set; }
    }
    /// <summary>
    /// Extended JWT payload to match the pubsub payload format
    /// </summary>
    public class PubSubPayload: JsonWebSignature.Payload
    {
        [JsonProperty("email")]
        public string Email { get; set; }
        [JsonProperty("email_verified")]
        public string EmailVerified { get; set; }
    }

}
