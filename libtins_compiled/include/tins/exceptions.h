/*
 * Copyright (c) 2014, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef TINS_EXCEPTIONS_H
#define TINS_EXCEPTIONS_H

#include <string>
#include <stdexcept>

namespace Tins {
/**
 * \brief Base class for all libtins exceptions.
 */
class exception_base : public std::runtime_error {
public:
    exception_base() 
    : std::runtime_error(std::string()) { }

    exception_base(const std::string& message) 
    : std::runtime_error(message) { }
};

/**
 * \brief Exception thrown when an option is not found.
 */
class option_not_found : exception_base {
public:
    // try to avoid allocations by doing this.
    const char* what() const throw() {
        return "Option not found";
    }
};

/**
 * \brief Exception thrown when a malformed packet is parsed.
 */
class malformed_packet : public exception_base {
public:
    const char* what() const throw() {
        return "Malformed packet";
    }
};

/**
 * \brief Exception thrown when a PDU is not found when using PDU::rfind_pdu.
 */
class pdu_not_found : public exception_base {
public:
    const char* what() const throw() {
        return "PDU not found";
    }
};

/**
 * \brief Exception thrown when PDU::send requires a valid interface,
 * but an invalid is used.
 */
class invalid_interface : public exception_base {
public:
    const char* what() const throw() {
        return "Invalid interface";
    }
};

/**
 * \brief Exception thrown when a field is not present in frame.
 */
class field_not_present : public exception_base {
public:
    const char* what() const throw() {
        return "Field not present";
    }
};

/**
 * \brief Exception thrown when PacketSender fails to open a socket.
 */
class socket_open_error : public exception_base {
public:
    socket_open_error(const std::string &msg)
    : exception_base(msg) { }
};

/**
 * \brief Exception thrown when PacketSender fails to close a socket.
 */
class socket_close_error : exception_base {
public:
    socket_close_error(const std::string &msg)
    : exception_base(msg) { }
};

/**
 * \brief Exception thrown when PacketSender fails to write on a socket.
 */
class socket_write_error : public exception_base {
public:
    socket_write_error(const std::string &msg)
    : exception_base(msg) { }
};

/**
 * \brief Exception thrown when an invalid socket type is provided
 * to PacketSender.
 */
class invalid_socket_type : public exception_base {
public:
    const char *what() const throw() {
        return "The provided socket type is invalid";
    }
};

/**
 * \brief Exception thrown when an unkown link layer PDU type is
 * found while sniffing.
 */
class unknown_link_type : public exception_base {
public:
    const char *what() const throw() {
        return "The sniffed link layer PDU type is unknown";
    }
};

/**
 * \brief Exception thrown when a malformed option is found.
 */
class malformed_option : public exception_base {
public:
    const char *what() const throw() {
        return "Malformed option";
    }
};

/**
 * \brief Exception thrown when a call to tins_cast fails.
 */
class bad_tins_cast : public exception_base {
public:
    const char *what() const throw() {
        return "Bad Tins cast";
    }
};

/**
 * \brief Exception thrown when sniffing a protocol that
 * has been disabled at compile time.
 */
class protocol_disabled : public exception_base {
public:
    const char *what() const throw() {
        return "Protocol disabled";
    }
};

/**
 * \brief Exception thrown when a payload is too large to fit
 * into a PDUOption.
 */
class option_payload_too_large : public exception_base {
public:
    const char *what() const throw() {
        return "Option payload too large";
    }
};

namespace Crypto {
namespace WPA2 {
    /**
     * \brief Exception thrown when an invalid WPA2 handshake is found.
     */
    class invalid_handshake : public exception_base {
    public:
        const char *what() const throw() {
            return "Invalid WPA2 handshake";
        }
    };
} // WPA2
} // Crypto

} // Tins

#endif // TINS_EXCEPTIONS_H
