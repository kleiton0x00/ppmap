echo [+] Creating a Go module
go mod init ppmap

echo [+] Installing the required library
go get github.com/chromedp/chromedp

echo [+] Building the binary
go build

echo [+] Moving the compiled binary to /usr/bin
sudo mv ppmap /usr/bin

echo [+] Setup finished!
