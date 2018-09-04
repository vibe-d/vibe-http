module vibe.http.internal.http2;
import vibe.core.stream;

/*
 *  6.5.1.  SETTINGS Format
 *
 *   The payload of a SETTINGS frame consists of zero or more parameters,
 *   each consisting of an unsigned 16-bit setting identifier and an
 *   unsigned 32-bit value.
 *
 *   +-------------------------------+
 *   |       Identifier (16)         |
 *   +-------------------------------+-------------------------------+
 *   |                        Value (32)                             |
 *   +---------------------------------------------------------------+
 *                        Figure 10: Setting Format
 *
 *   6.5.2.  Defined SETTINGS Parameters
 *
 *   The following parameters are defined:
 *
 *   SETTINGS_HEADER_TABLE_SIZE (0x1):  Allows the sender to inform the
 *     remote endpoint of the maximum size of the header compression
 *     table used to decode header blocks, in octets.  The encoder can
 *     select any size equal to or less than this value by using
 *     signaling specific to the header compression format inside a
 *     header block (see [COMPRESSION]).  The initial value is 4,096
 *     octets.
 *
 *   SETTINGS_ENABLE_PUSH (0x2):  This setting can be used to disable
 *      server push (Section 8.2).  An endpoint MUST NOT send a
 *      PUSH_PROMISE frame if it receives this parameter set to a value of
 *      0.  An endpoint that has both set this parameter to 0 and had it
 *      acknowledged MUST treat the receipt of a PUSH_PROMISE frame as a
 *      connection error (Section 5.4.1) of type PROTOCOL_ERROR.
 *
 *      The initial value is 1, which indicates that server push is
 *      permitted.  Any value other than 0 or 1 MUST be treated as a
 *      connection error (Section 5.4.1) of type PROTOCOL_ERROR.
 *
 *    SETTINGS_MAX_CONCURRENT_STREAMS (0x3):  Indicates the maximum number
 *      of concurrent streams that the sender will allow.  This limit is
 *      directional: it applies to the number of streams that the sender
 *      permits the receiver to create.  Initially, there is no limit to
 *      this value.  It is recommended that this value be no smaller than
 *      100, so as to not unnecessarily limit parallelism.
 *
 *      A value of 0 for SETTINGS_MAX_CONCURRENT_STREAMS SHOULD NOT be
 *      treated as special by endpoints.  A zero value does prevent the
 *      creation of new streams; however, this can also happen for any
 *      limit that is exhausted with active streams.  Servers SHOULD only
 *      set a zero value for short durations; if a server does not wish to
 *      accept requests, closing the connection is more appropriate.
 *
 *    SETTINGS_INITIAL_WINDOW_SIZE (0x4):  Indicates the sender's initial
 *       window size (in octets) for stream-level flow control.  The
 *       initial value is 2^16-1 (65,535) octets.
 *
 *       This setting affects the window size of all streams (see
 *       Section 6.9.2).
 *
 *       Values above the maximum flow-control window size of 2^31-1 MUST
 *       be treated as a connection error (Section 5.4.1) of type
 *       FLOW_CONTROL_ERROR.
 *
 *    SETTINGS_MAX_FRAME_SIZE (0x5):  Indicates the size of the largest
 *       frame payload that the sender is willing to receive, in octets.
 *
 *       The initial value is 2^14 (16,384) octets.  The value advertised
 *       by an endpoint MUST be between this initial value and the maximum
 *       allowed frame size (2^24-1 or 16,777,215 octets), inclusive.
 *       Values outside this range MUST be treated as a connection error
 *       (Section 5.4.1) of type PROTOCOL_ERROR.
 *
 *    SETTINGS_MAX_HEADER_LIST_SIZE (0x6):  This advisory setting informs a
 *       peer of the maximum size of header list that the sender is
 *       prepared to accept, in octets.  The value is based on the
 *       uncompressed size of header fields, including the length of the
 *       name and value in octets plus an overhead of 32 octets for each
 *       header field.
 *
 *       For any given request, a lower limit than what is advertised MAY
 *       be enforced.  The initial value of this setting is unlimited.
 *
 *   An endpoint that receives a SETTINGS frame with any unknown or
 *   unsupported identifier MUST ignore that setting.
*/
alias HTTP2SettingsID = ushort;
alias HTTP2SettingsValue = uint;

enum  HTTP2SettingsParameters {
    headerTableSize                 = 0x1,
    enablePush                      = 0x2,
    maxConcurrentStreams            = 0x3,
    initialWindowSize               = 0x4,
    maxFrameSize                    = 0x5,
    maxHeaderListSize               = 0x6
}


struct HTTP2Settings {

    alias H2Params = HTTP2SettingsParameters;

    private struct Setting {
        HTTP2SettingsID id;
        HTTP2SettingsValue value;
    }

    Setting headerTableSize         = {H2Params.headerTableSize, 4096};

    Setting enablePush              = {H2Params.enablePush, 1};

    // UNLIMITED, 100 is the minimum recommended value (TODO discuss)
    Setting maxConcurrentStreams    = {H2Params.maxConcurrentStreams, 100};

    Setting initialWindowSize       = {H2Params.initialWindowSize, 65535};

    Setting maxFrameSize            = {H2Params.maxFrameSize, 16384};

    // UNLIMITED, (TODO discuss);
    Setting maxHeaderListSize;

    /**
      * Convert a ushort request code to the corresponding string (see RFC)
      */
    string toString(uint code) {
        switch(code) {
            case H2Params.headerTableSize:
                return "SETTINGS_HEADER_TABLE_SIZE";
            case H2Params.enablePush:
                return "SETTINGS_ENABLE_PUSH";
            case H2Params.maxConcurrentStreams:
                return "SETTINGS_MAX_CONCURRENT_STREAMS";
            case H2Params.initialWindowSize:
                return "SETTINGS_INITIAL_WINDOW_SIZE";
            case H2Params.maxFrameSize:
                return "SETTINGS_MAX_FRAME_SIZE";
            case H2Params.maxHeaderListSize:
                return "SETTINGS_MAX_HEADER_LIST_SIZE";
            default:
                // TODO error codes
                assert(false, "Unrecognized SETTINGS code (TODO Errors)");
        }
    }
}



private void handleHTTP2Connection(ConnectionStream)(ConnectionStream connection)
	if (isConnectionStream!ConnectionStream)
{
}

