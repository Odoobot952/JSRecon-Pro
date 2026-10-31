// Optional manual Playwright check against the bundled loopback-only lab.
const { chromium } = require('playwright');
(async()=>{
 const url='http://127.0.0.1:8765/';
 const u=new URL(url);
 if(!['127.0.0.1','localhost','[::1]'].includes(u.hostname)) throw new Error('Only loopback targets are allowed.');
 const browser=await chromium.launch({headless:true});
 const page=await browser.newPage();
 const issues=[];
 page.on('pageerror',e=>issues.push(e.message));
 await page.goto(url,{waitUntil:'domcontentloaded'});
 console.log(JSON.stringify({url,title:await page.title(),pageErrors:issues},null,2));
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
