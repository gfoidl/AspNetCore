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
    internal class KestrelTrace : IKestrelTrace
    {
        private static readonly Action<ILogger, string, Exception?> _connectionStart =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(1, "ConnectionStart"), @"Connection id ""{ConnectionId}"" started.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception?> _connectionStop =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(2, "ConnectionStop"), @"Connection id ""{ConnectionId}"" stopped.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception?> _connectionPause =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(4, "ConnectionPause"), @"Connection id ""{ConnectionId}"" paused.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception?> _connectionResume =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(5, "ConnectionResume"), @"Connection id ""{ConnectionId}"" resumed.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception?> _connectionKeepAlive =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(9, "ConnectionKeepAlive"), @"Connection id ""{ConnectionId}"" completed keep alive response.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception?> _connectionDisconnect =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(10, "ConnectionDisconnect"), @"Connection id ""{ConnectionId}"" disconnecting.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, Exception> _applicationError =
            LoggerMessage.Define<string, string>(LogLevel.Error, new EventId(13, "ApplicationError"), @"Connection id ""{ConnectionId}"", Request id ""{TraceIdentifier}"": An unhandled exception was thrown by the application.", skipEnabledCheck: true);

        private static readonly Action<ILogger, Exception?> _notAllConnectionsClosedGracefully =
            LoggerMessage.Define(LogLevel.Debug, new EventId(16, "NotAllConnectionsClosedGracefully"), "Some connections failed to close gracefully during server shutdown.");

        private static readonly Action<ILogger, string, string, Exception> _connectionBadRequest =
            LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(17, "ConnectionBadRequest"), @"Connection id ""{ConnectionId}"" bad request data: ""{message}""", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, long, Exception?> _connectionHeadResponseBodyWrite =
            LoggerMessage.Define<string, long>(LogLevel.Debug, new EventId(18, "ConnectionHeadResponseBodyWrite"), @"Connection id ""{ConnectionId}"" write of ""{count}"" body bytes to non-body HEAD response.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception> _requestProcessingError =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(20, "RequestProcessingError"), @"Connection id ""{ConnectionId}"" request processing ended abnormally.", skipEnabledCheck: true);

        private static readonly Action<ILogger, Exception?> _notAllConnectionsAborted =
            LoggerMessage.Define(LogLevel.Debug, new EventId(21, "NotAllConnectionsAborted"), "Some connections failed to abort during server shutdown.");

        private static readonly Action<ILogger, DateTimeOffset, TimeSpan, TimeSpan, Exception?> _heartbeatSlow =
            LoggerMessage.Define<DateTimeOffset, TimeSpan, TimeSpan>(LogLevel.Warning, new EventId(22, "HeartbeatSlow"), @"As of ""{now}"", the heartbeat has been running for ""{heartbeatDuration}"" which is longer than ""{interval}"". This could be caused by thread pool starvation.");

        private static readonly Action<ILogger, string, Exception?> _applicationNeverCompleted =
            LoggerMessage.Define<string>(LogLevel.Critical, new EventId(23, "ApplicationNeverCompleted"), @"Connection id ""{ConnectionId}"" application never completed.");

        private static readonly Action<ILogger, string, Exception?> _connectionRejected =
            LoggerMessage.Define<string>(LogLevel.Warning, new EventId(24, "ConnectionRejected"), @"Connection id ""{ConnectionId}"" rejected because the maximum number of concurrent connections has been reached.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, Exception?> _requestBodyStart =
            LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(25, "RequestBodyStart"), @"Connection id ""{ConnectionId}"", Request id ""{TraceIdentifier}"": started reading request body.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, Exception?> _requestBodyDone =
            LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(26, "RequestBodyDone"), @"Connection id ""{ConnectionId}"", Request id ""{TraceIdentifier}"": done reading request body.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string?, double, Exception?> _requestBodyMinimumDataRateNotSatisfied =
            LoggerMessage.Define<string, string?, double>(LogLevel.Debug, new EventId(27, "RequestBodyMinimumDataRateNotSatisfied"), @"Connection id ""{ConnectionId}"", Request id ""{TraceIdentifier}"": the request timed out because it was not sent by the client at a minimum of {Rate} bytes/second.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string?, Exception?> _responseMinimumDataRateNotSatisfied =
            LoggerMessage.Define<string, string?>(LogLevel.Debug, new EventId(28, "ResponseMinimumDataRateNotSatisfied"), @"Connection id ""{ConnectionId}"", Request id ""{TraceIdentifier}"": the connection was closed because the response was not read by the client at the specified minimum data rate.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception> _http2ConnectionError =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(29, "Http2ConnectionError"), @"Connection id ""{ConnectionId}"": HTTP/2 connection error.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception> _http2StreamError =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(30, "Http2StreamError"), @"Connection id ""{ConnectionId}"": HTTP/2 stream error.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, int, Exception> _hpackDecodingError =
            LoggerMessage.Define<string, int>(LogLevel.Debug, new EventId(31, "HPackDecodingError"), @"Connection id ""{ConnectionId}"": HPACK decoding error while decoding headers for stream ID {StreamId}.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, Exception?> _requestBodyNotEntirelyRead =
            LoggerMessage.Define<string, string>(LogLevel.Information, new EventId(32, "RequestBodyNotEntirelyRead"), @"Connection id ""{ConnectionId}"", Request id ""{TraceIdentifier}"": the application completed without reading the entire request body.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, Exception?> _requestBodyDrainTimedOut =
            LoggerMessage.Define<string, string>(LogLevel.Information, new EventId(33, "RequestBodyDrainTimedOut"), @"Connection id ""{ConnectionId}"", Request id ""{TraceIdentifier}"": automatic draining of the request body timed out after taking over 5 seconds.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, Exception?> _applicationAbortedConnection =
            LoggerMessage.Define<string, string>(LogLevel.Information, new EventId(34, "ApplicationAbortedConnection"), @"Connection id ""{ConnectionId}"", Request id ""{TraceIdentifier}"": the application aborted the connection.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Http2ErrorCode, Exception> _http2StreamResetAbort =
            LoggerMessage.Define<string, Http2ErrorCode>(LogLevel.Debug, new EventId(35, "Http2StreamResetAbort"),
                @"Trace id ""{TraceIdentifier}"": HTTP/2 stream error ""{error}"". A Reset is being sent to the stream.");

        private static readonly Action<ILogger, string, Exception?> _http2ConnectionClosing =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(36, "Http2ConnectionClosing"),
                @"Connection id ""{ConnectionId}"" is closing.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, int, Exception?> _http2ConnectionClosed =
            LoggerMessage.Define<string, int>(LogLevel.Debug, new EventId(48, "Http2ConnectionClosed"),
                @"Connection id ""{ConnectionId}"" is closed. The last processed stream ID was {HighestOpenedStreamId}.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Http2FrameType, int, int, object, Exception?> _http2FrameReceived =
            LoggerMessage.Define<string, Http2FrameType, int, int, object>(LogLevel.Trace, new EventId(37, "Http2FrameReceived"),
                @"Connection id ""{ConnectionId}"" received {type} frame for stream ID {id} with length {length} and flags {flags}.",
                skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Http2FrameType, int, int, object, Exception?> _http2FrameSending =
            LoggerMessage.Define<string, Http2FrameType, int, int, object>(LogLevel.Trace, new EventId(49, "Http2FrameSending"),
                @"Connection id ""{ConnectionId}"" sending {type} frame for stream ID {id} with length {length} and flags {flags}.",
                skipEnabledCheck: true);

        private static readonly Action<ILogger, string, int, Exception> _hpackEncodingError =
            LoggerMessage.Define<string, int>(LogLevel.Information, new EventId(38, "HPackEncodingError"),
                @"Connection id ""{ConnectionId}"": HPACK encoding error while encoding headers for stream ID {StreamId}.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception?> _connectionAccepted =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(39, "ConnectionAccepted"), @"Connection id ""{ConnectionId}"" accepted.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception?> _http2MaxConcurrentStreamsReached =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(40, "Http2MaxConcurrentStreamsReached"),
                @"Connection id ""{ConnectionId}"" reached the maximum number of concurrent HTTP/2 streams allowed.", skipEnabledCheck: true);

        private static readonly Action<ILogger, Exception?> _invalidResponseHeaderRemoved =
            LoggerMessage.Define(LogLevel.Warning, new EventId(41, "InvalidResponseHeaderRemoved"),
                "One or more of the following response headers have been removed because they are invalid for HTTP/2 and HTTP/3 responses: 'Connection', 'Transfer-Encoding', 'Keep-Alive', 'Upgrade' and 'Proxy-Connection'.");

        private static readonly Action<ILogger, string, Exception> _http3ConnectionError =
               LoggerMessage.Define<string>(LogLevel.Debug, new EventId(42, "Http3ConnectionError"), @"Connection id ""{ConnectionId}"": HTTP/3 connection error.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, Exception?> _http3ConnectionClosing =
            LoggerMessage.Define<string>(LogLevel.Debug, new EventId(43, "Http3ConnectionClosing"),
                @"Connection id ""{ConnectionId}"" is closing.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, long, Exception?> _http3ConnectionClosed =
            LoggerMessage.Define<string, long>(LogLevel.Debug, new EventId(44, "Http3ConnectionClosed"),
                @"Connection id ""{ConnectionId}"" is closed. The last processed stream ID was {HighestOpenedStreamId}.", skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, Exception> _http3StreamAbort =
            LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(45, "Http3StreamAbort"),
                @"Trace id ""{TraceIdentifier}"": HTTP/3 stream error ""{error}"". An abort is being sent to the stream.",
                skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, long, long, Exception?> _http3FrameReceived =
            LoggerMessage.Define<string, string, long, long>(LogLevel.Trace, new EventId(46, "Http3FrameReceived"),
                @"Connection id ""{ConnectionId}"" received {type} frame for stream ID {id} with length {length}.",
                skipEnabledCheck: true);

        private static readonly Action<ILogger, string, string, long, long, Exception?> _http3FrameSending =
            LoggerMessage.Define<string, string, long, long>(LogLevel.Trace, new EventId(47, "Http3FrameSending"),
                @"Connection id ""{ConnectionId}"" sending {type} frame for stream ID {id} with length {length}.",
                skipEnabledCheck: true);

        protected readonly ILogger _logger;

        public KestrelTrace(ILogger logger)
        {
            _logger = logger;
        }

        public virtual void ConnectionAccepted(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionAccepted(_logger, connection.ConnectionId, null);
        }

        public virtual void ConnectionStart(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionStart(_logger, connection.ConnectionId, null);
        }

        public virtual void ConnectionStop(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionStop(_logger, connection.ConnectionId, null);
        }

        public virtual void ConnectionPause(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionPause(_logger, connection.ConnectionId, null);
        }

        public virtual void ConnectionResume(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionResume(_logger, connection.ConnectionId, null);
        }

        public virtual void ConnectionKeepAlive(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionKeepAlive(_logger, connection.ConnectionId, null);
        }

        public virtual void ConnectionRejected(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Warning)) return;

            _connectionRejected(_logger, connection.ConnectionId, null);
        }

        public virtual void ConnectionDisconnect(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionDisconnect(_logger, connection.ConnectionId, null);
        }

        public virtual void ApplicationError(HttpProtocol httpProtocol, Exception ex)
        {
            if (!_logger.IsEnabled(LogLevel.Error)) return;

            _applicationError(_logger, httpProtocol.ConnectionId, httpProtocol.TraceIdentifier, ex);
        }

        public virtual void ConnectionHeadResponseBodyWrite(BaseConnectionContext connection, long count)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionHeadResponseBodyWrite(_logger, connection.ConnectionId, count, null);
        }

        public virtual void NotAllConnectionsClosedGracefully()
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _notAllConnectionsClosedGracefully(_logger, null);
        }

        public virtual void ConnectionBadRequest(BaseConnectionContext connection, AspNetCore.Http.BadHttpRequestException ex)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _connectionBadRequest(_logger, connection.ConnectionId, ex.Message, ex);
        }

        public virtual void RequestProcessingError(BaseConnectionContext connection, Exception ex)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _requestProcessingError(_logger, connection.ConnectionId, ex);
        }

        public virtual void NotAllConnectionsAborted()
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _notAllConnectionsAborted(_logger, null);
        }

        public virtual void HeartbeatSlow(TimeSpan heartbeatDuration, TimeSpan interval, DateTimeOffset now)
        {
            if (!_logger.IsEnabled(LogLevel.Warning)) return;

            _heartbeatSlow(_logger, now, heartbeatDuration, interval, null);
        }

        public virtual void ApplicationNeverCompleted(string connectionId)
        {
            _applicationNeverCompleted(_logger, connectionId, null);
        }

        public virtual void RequestBodyStart(BaseConnectionContext connection, string traceIdentifier)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _requestBodyStart(_logger, connection.ConnectionId, traceIdentifier, null);
        }

        public virtual void RequestBodyDone(BaseConnectionContext connection, string traceIdentifier)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _requestBodyDone(_logger, connection.ConnectionId, traceIdentifier, null);
        }

        public virtual void RequestBodyMinimumDataRateNotSatisfied(BaseConnectionContext connection, HttpProtocol? httpProtocol, double rate)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _requestBodyMinimumDataRateNotSatisfied(_logger, connection.ConnectionId, httpProtocol?.TraceIdentifier, rate, null);
        }

        public virtual void RequestBodyNotEntirelyRead(HttpProtocol httpProtocol)
        {
            if (!_logger.IsEnabled(LogLevel.Information)) return;

            _requestBodyNotEntirelyRead(_logger, httpProtocol.ConnectionId, httpProtocol.TraceIdentifier, null);
        }

        public virtual void RequestBodyDrainTimedOut(HttpProtocol httpProtocol)
        {
            if (!_logger.IsEnabled(LogLevel.Information)) return;

            _requestBodyDrainTimedOut(_logger, httpProtocol.ConnectionId, httpProtocol.TraceIdentifier, null);
        }

        public virtual void ResponseMinimumDataRateNotSatisfied(BaseConnectionContext connection, string? traceIdentifier)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _responseMinimumDataRateNotSatisfied(_logger, connection.ConnectionId, traceIdentifier, null);
        }

        public virtual void ApplicationAbortedConnection(HttpProtocol httpProtocol)
        {
            if (!_logger.IsEnabled(LogLevel.Information)) return;

            _applicationAbortedConnection(_logger, httpProtocol.ConnectionId, httpProtocol.TraceIdentifier, null);
        }

        public virtual void Http2ConnectionError(BaseConnectionContext connection, Http2ConnectionErrorException ex)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http2ConnectionError(_logger, connection.ConnectionId, ex);
        }

        public virtual void Http2ConnectionClosing(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http2ConnectionClosing(_logger, connection.ConnectionId, null);
        }

        public virtual void Http2ConnectionClosed(BaseConnectionContext connection, int highestOpenedStreamId)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http2ConnectionClosed(_logger, connection.ConnectionId, highestOpenedStreamId, null);
        }

        public virtual void Http2StreamError(BaseConnectionContext connection, Http2StreamErrorException ex)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http2StreamError(_logger, connection.ConnectionId, ex);
        }

        public void Http2StreamResetAbort(string traceIdentifier, Http2ErrorCode error, ConnectionAbortedException abortReason)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http2StreamResetAbort(_logger, traceIdentifier, error, abortReason);
        }

        public virtual void HPackDecodingError(BaseConnectionContext connection, int streamId, HPackDecodingException ex)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _hpackDecodingError(_logger, connection.ConnectionId, streamId, ex);
        }

        public virtual void HPackEncodingError(BaseConnectionContext connection, int streamId, HPackEncodingException ex)
        {
            if (!_logger.IsEnabled(LogLevel.Information)) return;

            _hpackEncodingError(_logger, connection.ConnectionId, streamId, ex);
        }

        public void Http2FrameReceived(BaseConnectionContext connection, Http2Frame frame)
        {
            if (!_logger.IsEnabled(LogLevel.Trace)) return;

            _http2FrameReceived(_logger, connection.ConnectionId, frame.Type, frame.StreamId, frame.PayloadLength, frame.ShowFlags(), null);
        }

        public void Http2FrameSending(BaseConnectionContext connection, Http2Frame frame)
        {
            if (!_logger.IsEnabled(LogLevel.Trace)) return;

            _http2FrameSending(_logger, connection.ConnectionId, frame.Type, frame.StreamId, frame.PayloadLength, frame.ShowFlags(), null);
        }

        public void Http2MaxConcurrentStreamsReached(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http2MaxConcurrentStreamsReached(_logger, connection.ConnectionId, null);
        }

        public void InvalidResponseHeaderRemoved()
        {
            _invalidResponseHeaderRemoved(_logger, null);
        }

        public void Http3ConnectionError(BaseConnectionContext connection, Http3ConnectionErrorException ex)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http3ConnectionError(_logger, connection.ConnectionId, ex);
        }

        public void Http3ConnectionClosing(BaseConnectionContext connection)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http3ConnectionClosing(_logger, connection.ConnectionId, null);
        }

        public void Http3ConnectionClosed(BaseConnectionContext connection, long highestOpenedStreamId)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http3ConnectionClosed(_logger, connection.ConnectionId, highestOpenedStreamId, null);
        }

        public void Http3StreamAbort(string traceIdentifier, Http3ErrorCode error, ConnectionAbortedException abortReason)
        {
            if (!_logger.IsEnabled(LogLevel.Debug)) return;

            _http3StreamAbort(_logger, traceIdentifier, Http3Formatting.ToFormattedErrorCode(error), abortReason);
        }

        public void Http3FrameReceived(BaseConnectionContext connection, long streamId, Http3RawFrame frame)
        {
            if (!_logger.IsEnabled(LogLevel.Trace)) return;

            _http3FrameReceived(_logger, connection.ConnectionId, Http3Formatting.ToFormattedType(frame.Type), streamId, frame.Length, null);
        }

        public void Http3FrameSending(BaseConnectionContext connection, long streamId, Http3RawFrame frame)
        {
            if (!_logger.IsEnabled(LogLevel.Trace)) return;

            _http3FrameSending(_logger, connection.ConnectionId, Http3Formatting.ToFormattedType(frame.Type), streamId, frame.Length, null);
        }

        public virtual void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => _logger.Log(logLevel, eventId, state, exception, formatter);

        public virtual bool IsEnabled(LogLevel logLevel) => _logger.IsEnabled(logLevel);

        public virtual IDisposable BeginScope<TState>(TState state) => _logger.BeginScope(state);
    }
}
