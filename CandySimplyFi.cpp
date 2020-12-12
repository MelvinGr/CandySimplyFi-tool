#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#if defined(_WIN32) || defined(_WIN64)
#pragma comment(lib, "ws2_32.lib")
#include <ws2tcpip.h>
#define close(s) closesocket(s)
#else
// g++ CandySimplyFi.cpp -o simplyfi
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#define SOCKET int
#endif

namespace xorknown
{
	// Based on https://github.com/Alamot/code-snippets/blob/master/crypto/xorknown.py
	const unsigned char ignore_code = 0xff;
	const unsigned char max_key_length = 16 + 1;
	const bool printable_key = true;

	std::string multiply_string(const std::string& str, unsigned int count)
	{
		std::stringstream out;
		while (count--)
			out << str;
		return out.str();
	}

	bool is_printable(const std::string& text)
	{
		for (const char ch : text)
		{
			if (ch != ignore_code && ch != '\r' && ch != '\n' && ch != '\t' && !isprint(ch))
				return false;
		}

		return true;
	}

	std::string find_xor_key(const std::string &data, const std::string known_plaintext)
	{
		if (known_plaintext.length() > max_key_length)
		{
			std::cerr << "error: The length of the known plaintext is greater than 16!" << std::endl;
			return "";
		}

		//std::cout << "Searching XOR-encrypted " << filename << " for string '" << known_plaintext << "' (max_key_length = " << (max_key_length - 1) << ")" << std::endl;

		for (size_t pp = 0; pp < data.size() - known_plaintext.length(); pp++) // Try known plaintext in every position
		{
			std::string partial_key;
			for (size_t j = 0; j < known_plaintext.length(); j++)
			{
				if (known_plaintext[j] == ignore_code)
					partial_key.push_back(ignore_code);
				else
					partial_key.push_back(data[pp + j] ^ known_plaintext[j]);
			}

			if (!printable_key || is_printable(partial_key))
			{
				for (size_t kl = partial_key.size(); kl < max_key_length; kl++) // Try different key lengths
				{
					for (size_t kp = 0; kp < kl; kp++) // Try different partial key positions
					{
						std::string expanded_key = partial_key + multiply_string(std::to_string(ignore_code), kl - partial_key.length());
						std::rotate(expanded_key.begin(), expanded_key.begin() + kp, expanded_key.end()); // rotate to the left

						std::string decrypted_text;

						for (size_t x = 0; x < data.size(); x++) // Try to decrypt the encoded text
						{
							if (expanded_key[x % expanded_key.length()] == ignore_code)
								decrypted_text.push_back(ignore_code);
							else
								decrypted_text.push_back(data[x] ^ expanded_key[x % expanded_key.length()]);
						}

						if (is_printable(decrypted_text)) // Is the whole result printable?
						{
							if (known_plaintext.find(decrypted_text))
							{
								return expanded_key;
							}
						}
					}
				}
			}
		}

		return "";
	}

	std::string find_xor_key_list(const std::string &data, const std::vector<std::string> known_plaintexts)
	{
		for (const std::string& known_plaintext : known_plaintexts)
		{
			auto xor_key = find_xor_key(data, known_plaintext);
			if (xor_key.length() > 0)
				return xor_key;
		}

		return "";
	}
}

void xor_string(std::string& buffer, const std::string& key)
{
	for (size_t i = 0; i < buffer.size(); i++) {
		buffer[i] ^= key[i % key.length()];
	}
}

std::string get_candySimplify_data(const std::string& deviceIp, const std::string& method, short port = 80)
{
#if defined(_WIN32) || defined(_WIN64)
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cerr << "error: WSAStartup" << std::endl;
		return {};
	}
#endif

	SOCKET sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		std::cerr << "error: socket" << std::endl;
		return {};
	}

	struct sockaddr_in servAddr;
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(port);

	if (inet_pton(AF_INET, deviceIp.c_str(), &servAddr.sin_addr) <= 0)
	{
		std::cerr << "error: inet_pton" << std::endl;
		return {};
	}

	if (connect(sock, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0)
	{
		std::cerr << "error: connect" << std::endl;
		return {};
	}

	const std::string message = "GET /http-" + method + ".json?encrypted=1 HTTP/1.1\nHost: " + deviceIp + "\n\nConnection: close\r\n\r\n";
	send(sock, message.c_str(), message.length(), 0);

	int bytesRead;
	std::string hexContent;

	do {
		char buf[1024];
		bytesRead = recv(sock, buf, sizeof(buf), 0);
		for (int i = 0; i < bytesRead; i++)
			hexContent.push_back(buf[i]);
	} while (bytesRead > 0);

	close(sock);

	hexContent = hexContent.substr(hexContent.find_last_of("\r\n\r\n") + 1);
	if (hexContent.length() % 2 == 1)
		hexContent = "0" + hexContent;

	std::string output;
	for (size_t i = 0; i < hexContent.length(); i += 2)
		output.push_back((char)strtol(hexContent.substr(i, 2).c_str(), NULL, 16));
	return output;
}

void show_header(bool error = false)
{
	(error ? std::cerr : std::cout) << "## Candy Simply-Fi tool by Melvin Groenendaal ## " << std::endl;
}

int main(int argc, char* argv[])
{
	if ((argc == 3 && strcmp(argv[2], "getkey") != 0 || argc < 3) && argc != 4) {
		show_header(true);
		std::cerr << "Usage to retreive key: " << argv[0] << " <ip> getkey" << std::endl;
		std::cerr << "Usage to get data    : " << argv[0] << " <ip> <key> <method: config, getStatistics, read>" << std::endl;
		return -1;
	}

	if (strcmp(argv[2], "getkey") == 0)
	{
		show_header();
		auto data = get_candySimplify_data(argv[1], "read");
		if (data.length() == 0)
		{
			std::cerr << "error: get_candySimplify_data, could not get data from server" << std::endl;
			return -2;
		}
		
		auto key = xorknown::find_xor_key_list(data, 
		{
			"{\"WiFiStatus\":\"0\"", 
			"{\"WiFiStatus\":\"1\"",
			"{\"StatoWiFi\":\"0\"",
			"{\"StatoWiFi\":\"1\"",
			"\"CheckUpState\":\""
			//"DryingManagerLev",
		});

		if (key.length() == 0)
		{
			std::cerr << "error: find_xor_key_list, could not find key" << std::endl;
			return -3;
		}
		else
			std::cout << "Found key: " << key << std::endl;
	}
	else
	{
		auto data = get_candySimplify_data(argv[1], argv[3]);
		if (data.length() == 0)
		{
			std::cerr << "error: get_candySimplify_data, could not get data from server" << std::endl;
			return -4;
		}

		xor_string(data, argv[2]);
		std::cout << data << std::endl;
	}

	return 0;
}
