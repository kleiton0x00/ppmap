# ppmap ![markdown_statistic](https://img.shields.io/github/downloads/kleiton0x00/ppmap/total)
A simple scanner/exploitation tool written in GO which automatically exploits known and existing gadgets (checks for specific variables in the global context) to perform XSS via Prototype Pollution. NOTE: The program only exploits known gadgets, but does not cover code analysis or any advanced Prototype Pollution exploitation, which may include custom gadgets.

## Requirements
Make sure to have Chromium installed. No need to worry, **setup.sh** will automatically install that for you.  

## Installation
- Run the following command to clone the repo: 
 ```bash
git clone https://github.com/kleiton0x00/ppmap.git
 ```
 - Change the directory to ppmap and execute **setup.sh**:  
```bash
cd ppmap/ && bash setup.sh
```  
That's it. Enjoy using ppmap!
  
- Note: If you face error during manually compiling or during the setup (for some reasons), you can download the precompiled one:  
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

- Identify if the website is vulnerable to Prototype Pollution by heuristic scan (via location.hash and location.search)
- Fingerprint the known gadgets (checks for specific variables in the global context)
- Display the final XSS payload which can be exploited

## Credits

Many thanks to @Tomnomnom for the inspiration: https://www.youtube.com/watch?v=Gv1nK6Wj8qM&t=1558s  
The workflow of this program is hugely based on this article: https://infosecwriteups.com/javascript-prototype-pollution-practice-of-finding-and-exploitation-f97284333b2  
The fingerprint javascript file is based on this git: https://gist.github.com/nikitastupin/b3b64a9f8c0eb74ce37626860193eaec

## In the news
- 14/06/21: [Intigriti Bug Bytes #131](https://blog.intigriti.com/2021/07/14/bug-bytes-131-credential-stuffing-in-bug-bounty-hijacking-shortlinks-hacker-shows/) - Tool of the week
- 26/06/21: [Hackin9](https://hakin9.org/ppmap-a-scanner-exploitation-tool/) - Article  
- 23/09/21: [GeeksForGeeks](https://www.geeksforgeeks.org/ppmap-a-scanner-or-exploitation-tool-written-in-go/) - Article  
- 22/10/21: [Hacktricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution) - Client Side Prototype Pollution  
- 04/06/22 [BlackArch Linux](https://github.com/BlackArch/blackarch-site/commit/68696c40be1629095cd547559ce078a4c77a7073) - Officially added in BlackArch Linux :tada:
