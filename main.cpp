#include <iostream>
#include <array>
#include <netdb.h>
#include <fetch/fetch.h>

auto main(int argc, char *argv[]) -> int {
    std::array<char, 4096> buf{};
    fetchIO *io = fetchGetURL("https://www.example.com", "4");
    if (io == nullptr) {
        std::cout << "fetchIO null" << std::endl;
        std::cout << "error: " << fetchLastErrString << std::endl;
        return 1;
    }
    int nbytes = fetchIO_read(io, buf.data(), buf.size());
    fetchIO_close(io);
    std::cout << buf.data() << std::endl;
    std::cout << "done" << std::endl;
    return 0;
}