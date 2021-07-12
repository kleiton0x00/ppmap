# ppmap
A simple scanner/exploitation tool written in GO which automatically exploits known and existing gadgets to perform XSS via Prototype Pollution. Performs everything automatically: from basic recon to XSS exploitation. NOTE: The program only exploits known gadgets, but does not cover code analysis or any advanced Prototype Pollution exploitation, which may include custom gadgets.

## Requirements
Make sure to have [chromedp](https://github.com/chromedp/chromedp) installed:  
```go get -u github.com/chromedp/chromedp```

## Installation
- Automatically  
  - Download the already compiled binary [here](https://github.com/kleiton0x00/ppmap/releases/tag/v1.0.1)

- Manually (compile it yourself)  
  - Clone the project:  
```git clone https://github.com/kleiton0x00/ppmap.git```  
  - Change directory to ppmap folder:  
```cd ~/ppmap```  
  - Build the binary  
```go build ppmap.go```  

## Usage

Using the program is very simple you can either:
- scan a directory/file:
```echo 'https://target.com/index.html' | ./ppmap```

- or endpoint:
```echo 'http://target.com/something/?page=home' | ./ppmap```

## Demo
![](https://i.imgur.com/05nvfwX.gif)

## Features

- Identify if the website is vulnerable to Prototype Pollution by heuristic scan
- Fingerprint the known gadgets
- Display the final exploit & ready to perform XSS

## Credits

Many thanks to @Tomnomnom for the inspiration https://www.youtube.com/watch?v=Gv1nK6Wj8qM&t=1558s  
The workflow of this program is hugely based on this article https://infosecwriteups.com/javascript-prototype-pollution-practice-of-finding-and-exploitation-f97284333b2  
The fingerprint javascript file is based on this git https://gist.github.com/nikitastupin/b3b64a9f8c0eb74ce37626860193eaec
