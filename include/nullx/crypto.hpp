#ifndef IOREMAP_NULLX_CRYPTO_HPP
#define IOREMAP_NULLX_CRYPTO_HPP

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <boost/asio.hpp>

#include <fstream>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#undef CRYPTOPP_ENABLE_NAMESPACE_WEAK

namespace ioremap {
namespace nullx {
namespace crypto {

template <typename Encoder, size_t Size>
static std::string encode(const byte (&digest)[Size])
{
	std::string signature;
	CryptoPP::StringSink sink(signature);
	Encoder encoder(NULL, false, 2048);
	encoder.Put2(digest, Size, true, true);
	encoder.TransferAllTo(sink);

	return std::move(signature);
}

template <size_t Size>
static std::string to_base64(const byte (&digest)[Size])
{
	return encode<CryptoPP::Base64Encoder>(digest);
}

template <size_t Size>
static std::string to_hex(const byte (&digest)[Size])
{
	return encode<CryptoPP::HexEncoder>(digest);
}

template <typename Algorithm>
static std::string calc_hash(const char *data, size_t size)
{
	byte digest[Algorithm::DIGESTSIZE];
	Algorithm hash;
	hash.Update(reinterpret_cast<const byte *>(data), size);
	hash.Final(digest);

	return to_base64(digest);
}

template <typename Algorithm>
static std::string calc_hash(const boost::asio::const_buffer &text)
{
	return calc_hash<Algorithm>(boost::asio::buffer_cast<const char *>(text), boost::asio::buffer_size(text));
}

template <typename Algorithm>
static std::string calc_hmac(const std::string &text, const std::string &token)
{
	byte digest[Algorithm::DIGESTSIZE];
	CryptoPP::HMAC<Algorithm> hmac(reinterpret_cast<const byte *>(token.c_str()), token.size());
	hmac.Update(reinterpret_cast<const byte *>(text.c_str()), text.size());
	hmac.Final(digest);

	return to_base64(digest);
}

static std::string get_random_string() {
	std::ifstream in("/dev/urandom");

	std::string data;
	data.resize(128);

	in.read(const_cast<char *>(data.data()), data.size());
	return calc_hash<CryptoPP::Weak::MD5>(data.data(), data.size());
}

}}} // namespace ioremap::nullx::crypto

#endif // IOREMAP_NULLX_CRYPTO_HPP
