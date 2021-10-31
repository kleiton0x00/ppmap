# ppmap
A simple scanner/exploitation tool written in GO which automatically exploits known and existing gadgets (checks for specific variables in the global context) to perform XSS via Prototype Pollution. NOTE: The program only exploits known gadgets, but does not cover code analysis or any advanced Prototype Pollution exploitation, which may include custom gadgets.

## Requirements
Make sure to have Chromium installed (Chrome will also do the job):  
```sudo apt-get install chromium-browser```

Make sure to have [chromedp](https://github.com/chromedp/chromedp) installed:  
```go get -u github.com/chromedp/chromedp```

## Installation
- The recommended way to install the software is to compile it yourself by executing:  
```go get -u github.com/kleiton0x00/ppmap.git```  
  Check if it is successfuly compiled by typing in the terminal: ```ppmap```
  
- If you face error during manually compiling (for some reasons), you can download the precompiled one:  
  - Download the already compiled binary [here](https://github.com/kleiton0x00/ppmap/releases)
  - Give it the permission to execute ```chmod +x ppmap```

## Usage

Using the program is very simple, you can either:
- scan a directory/file (or even just the website itself):  
```echo 'https://target.com' | ppmap```

- or endpoint:  
```echo 'http://target.com/something/?page=home' | ppmap```

For mass scanning:  
``` cat url.txt | ppmap``` where **url.txt** contains all url(s) in column.

## Demo
![](https://i.imgur.com/05nvfwX.gif)

Feel free to test the tool on the following websites as a part of demonstration and to also check if the software is working correctly:  
https://msrkp.github.io/pp/2.html  
https://ctf.nikitastupin.com/pp/known.html  
https://grey-acoustics.surge.sh

## Workflow

- Identify if the website is vulnerable to Prototype Pollution by heuristic scan
- Fingerprint the known gadgets (checks for specific variables in the global context)
- Display the final XSS payload which can be exploited

## Credits

Many thanks to @Tomnomnom for the inspiration: https://www.youtube.com/watch?v=Gv1nK6Wj8qM&t=1558s  
The workflow of this program is hugely based on this article: https://infosecwriteups.com/javascript-prototype-pollution-practice-of-finding-and-exploitation-f97284333b2  
The fingerprint javascript file is based on this git: https://gist.github.com/nikitastupin/b3b64a9f8c0eb74ce37626860193eaec

## In the news
- 14/06/21: [Intigriti Bug Bytes #131](https://blog.intigriti.com/2021/07/14/bug-bytes-131-credential-stuffing-in-bug-bounty-hijacking-shortlinks-hacker-shows/) - Tool of the week
- 26/06/21: [Hackin9](https://hakin9.org/ppmap-a-scanner-exploitation-tool/)
- 23/09/2021: [GeeksForGeeks](https://www.geeksforgeeks.org/ppmap-a-scanner-or-exploitation-tool-written-in-go/)
- 22/10/2021: [Hacktricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution) - Client Side Prototype Pollution
