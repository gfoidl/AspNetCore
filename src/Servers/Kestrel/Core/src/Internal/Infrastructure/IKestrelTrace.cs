// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Net.Http;
using System.Net.Http.HPack;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http2;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http3;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure
{
    internal interface IKestrelTrace : ILogger
    {
        void ConnectionAccepted(BaseConnectionContext connection);

        void ConnectionStart(BaseConnectionContext connection);

        void ConnectionStop(BaseConnectionContext connection);

        void ConnectionPause(BaseConnectionContext connection);

        void ConnectionResume(BaseConnectionContext connection);

        void ConnectionRejected(BaseConnectionContext connection);

        void ConnectionKeepAlive(BaseConnectionContext connection);

        void ConnectionDisconnect(BaseConnectionContext connection);

        void RequestProcessingError(BaseConnectionContext connection, Exception ex);

        void ConnectionHeadResponseBodyWrite(BaseConnectionContext connection, long count);

        void NotAllConnectionsClosedGracefully();

        void ConnectionBadRequest(BaseConnectionContext connection, AspNetCore.Http.BadHttpRequestException ex);

        void ApplicationError(HttpProtocol httpProtocol, Exception ex);

        void NotAllConnectionsAborted();

        void HeartbeatSlow(TimeSpan heartbeatDuration, TimeSpan interval, DateTimeOffset now);

        void ApplicationNeverCompleted(string connectionId);

        void RequestBodyStart(BaseConnectionContext connection, string traceIdentifier);

        void RequestBodyDone(BaseConnectionContext connection, string traceIdentifier);

        void RequestBodyNotEntirelyRead(HttpProtocol httpProtocol);

        void RequestBodyDrainTimedOut(HttpProtocol httpProtocol);

        void RequestBodyMinimumDataRateNotSatisfied(BaseConnectionContext connection, HttpProtocol? httpProtocol, double rate);

        void ResponseMinimumDataRateNotSatisfied(BaseConnectionContext connection, string? traceIdentifier);

        void ApplicationAbortedConnection(HttpProtocol httpProtocol);

        void Http2ConnectionError(BaseConnectionContext connection, Http2ConnectionErrorException ex);

        void Http2ConnectionClosing(BaseConnectionContext connection);

        void Http2ConnectionClosed(BaseConnectionContext connection, int highestOpenedStreamId);

        void Http2StreamError(BaseConnectionContext connection, Http2StreamErrorException ex);

        void Http2StreamResetAbort(string traceIdentifier, Http2ErrorCode error, ConnectionAbortedException abortReason);

        void HPackDecodingError(BaseConnectionContext connection, int streamId, HPackDecodingException ex);

        void HPackEncodingError(BaseConnectionContext connection, int streamId, HPackEncodingException ex);

        void Http2FrameReceived(BaseConnectionContext connection, Http2Frame frame);

        void Http2FrameSending(BaseConnectionContext connection, Http2Frame frame);

        void Http2MaxConcurrentStreamsReached(BaseConnectionContext connection);

        void InvalidResponseHeaderRemoved();

        void Http3ConnectionError(BaseConnectionContext connection, Http3ConnectionErrorException ex);

        void Http3ConnectionClosing(BaseConnectionContext connection);

        void Http3ConnectionClosed(BaseConnectionContext connection, long highestOpenedStreamId);

        void Http3StreamAbort(string traceIdentifier, Http3ErrorCode error, ConnectionAbortedException abortReason);

        void Http3FrameReceived(BaseConnectionContext connection, long streamId, Http3RawFrame frame);

        void Http3FrameSending(BaseConnectionContext connection, long streamId, Http3RawFrame frame);
    }
}
