import re
import asyncio
import os
from aiohttp import web
from pyrogram import Client, filters
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
import aiohttp
import warnings
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
import cloudscraper
import shlex
import time
from concurrent.futures import ThreadPoolExecutor

# Suppress SSL verification warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

# Bot configuration
API_ID = 23883349
API_HASH = "9ae2939989ed439ab91419d66b61a4a4"
BOT_TOKEN = "7842856490:AAGK3IHkatwgNAliRjF1orLCyohjLEUVK9g"
ADMIN_ID = 5429071679

# Get port from environment variable for Render compatibility
PORT = int(os.environ.get("PORT", 8080))

# Initialize the bot
app = Client("gateway_checker_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Optimized gateway detection patterns (keeping only the most reliable ones)
GATEWAYS = {
    "Stripe": [
        r"<script[^>]*src=['\"]https?://js\.stripe\.com/v\d/['\"]",
        r"stripe\.com/v\d/elements",
        r"Stripe\(['\"](?:pk_live|pk_test)_[0-9a-zA-Z]+['\"]",
    ],
    "Braintree": [
        r"<script[^>]*src=['\"]https?://js\.braintreegateway\.com/[^'\"]+['\"]",
        r"braintree\.client\.create",
    ],
    "PayPal": [
        r"paypal\.com/sdk/js",
        r"paypal\.Buttons",
    ],
    "Square": [
        r"square\.com/js/sq-payment-form",
        r"SqPaymentForm",
    ],
    "Amazon Pay": [
        r"amazon\.(payments|pay)\.",
        r"amazon\.Pay\.renderButton",
    ],
    "Klarna": [
        r"klarna\.com",
        r"klarna-checkout",
    ],
    "Adyen": [
        r"adyen\.com",
        r"AdyenCheckout",
    ],
    "Authorize.net": [
        r"accept\.authorize\.net",
        r"AcceptUI",
    ],
    "Worldpay": [
        r"worldpay\.com",
        r"worldpay\.js",
    ],
    "Cybersource": [
        r"cybersource\.com",
        r"flex\.cybersource",
    ],
    "2Checkout": [
        r"2checkout\.(com|js)",
        r"2co\.com",
    ],
    "WooCommerce": [
        r"woocommerce",
        r"wc-api",
    ]
}

# Optimized captcha detection patterns
CAPTCHA_TYPES = {
    "reCAPTCHA": [
        r"www\.google\.com/recaptcha/api\.js",
        r"grecaptcha\.",
    ],
    "hCaptcha": [
        r"hcaptcha\.com/1/api\.js",
        r"data-hcaptcha",
    ],
    "Arkose Labs": [
        r"arkoselabs\.com",
        r"funcaptcha",
    ],
    "GeeTest": [
        r"geetest\.com",
        r"initGeetest",
    ]
}

# Store registered users
registered_users = set()

# Executor for parallel processing
executor = ThreadPoolExecutor(max_workers=10)

async def check_gateway(url):
    """
    Enhanced gateway checking with advanced detection methods using cloudscraper
    """
    start_time = time.time()
    try:
        scraper = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'mobile': False
            }
        )
        
        response = await asyncio.to_thread(
            lambda: scraper.get(
                url,
                timeout=10,  # Reduced timeout for faster checks
                verify=False
            )
        )

        html = response.text
        status_code = response.status_code

        # Parallel gateway detection for improved performance
        def check_gateway_patterns(gateway, patterns):
            if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                return gateway
            return None

        gateway_tasks = []
        for gateway, patterns in GATEWAYS.items():
            gateway_tasks.append((gateway, patterns))
        
        # Run gateway detection in parallel
        gateways_found = []
        with ThreadPoolExecutor(max_workers=len(GATEWAYS)) as executor:
            results = list(executor.map(lambda x: check_gateway_patterns(*x), gateway_tasks))
            gateways_found = [r for r in results if r]

        # Captcha detection
        captcha_detected = False
        captcha_types = []
        for captcha_type, patterns in CAPTCHA_TYPES.items():
            if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                captcha_detected = True
                captcha_types.append(captcha_type)

        # Cloudflare detection (improved)
        cloudflare_detected = bool(re.search(r"cloudflare", html, re.IGNORECASE)) or \
                             'cf-ray' in response.headers or \
                             any('cloudflare' in header.lower() for header in response.headers)

        # Enhanced security features detection
        security_features = []
        security_patterns = {
            "🔒 3D Secure": r"3D(-|\s)?Secure",
            "🔑 CVV Required": r"CVV|CVC|Security Code",
            "🔐 SSL/TLS": r"ssl|tls|https",
            "🛡️ Encryption": r"encryption|encrypted",
            "🧱 Firewall": r"firewall",
            "✅ Secure Payment": r"secure\s+payment|security\s+verified",
            "💳 PCI DSS": r"PCI|DSS",
            "🚫 Fraud Protection": r"fraud|protection",
            "💠 Verified by Visa": r"verified\s+by\s+visa",
            "🔰 Mastercard SecureCode": r"mastercard\s+secure\s+code"
        }
        
        for feature, pattern in security_patterns.items():
            if re.search(pattern, html, re.IGNORECASE):
                security_features.append(feature)

        # Status indicators with emojis
        status_indicators = {
            200: "✅",
            201: "✅",
            301: "↪️",
            302: "↪️",
            400: "⚠️",
            401: "🔒",
            403: "⛔",
            404: "❌",
            500: "💥",
            503: "⚡"
        }
        status_icon = status_indicators.get(status_code, "ℹ️")
        
        # Calculate response time
        response_time = round(time.time() - start_time, 2)

        return {
            "status_code": status_code,
            "status_icon": status_icon,
            "gateways": gateways_found,
            "captcha": {
                "detected": captcha_detected,
                "types": captcha_types
            },
            "cloudflare": cloudflare_detected,
            "security_features": security_features,
            "response_time": response_time
        }

    except Exception as e:
        return {"error": f"{str(e)}", "response_time": round(time.time() - start_time, 2)}

@app.on_message(filters.command("start"))
async def start_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        start_text = (
            "✨ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 𝗕𝗼𝘁 ✨\n\n"
            "🔍 Discover payment systems with precision\n\n"
            "🚀 Quick Start:\n"
            "• Register with /register\n"
            "• Check URLs with /chk\n"
            "• Process bulk URLs with /txt\n"
            "• Search URLs with /search\n\n"
            "🌟 Ready to uncover payment gateways?"
        )
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Register Now", callback_data="register")]
        ])
        await message.reply(start_text, reply_markup=keyboard, reply_to_message_id=message.id)
    else:
        welcome_back = (
            "🌟 𝗪𝗲𝗹𝗰𝗼𝗺𝗲 𝗕𝗮𝗰𝗸!\n\n"
            "Ready for more gateway discoveries?\n\n"
            "📌 Commands:\n"
            "• /chk - Check URLs\n"
            "• /txt - Process bulk URLs\n"
            "• /search - Find new URLs\n"
            "• /about - Bot information\n\n"
            "💫 Let's continue exploring!"
        )
        await message.reply(welcome_back, reply_to_message_id=message.id)

@app.on_callback_query(filters.regex("^register$"))
async def register_callback(client, callback_query):
    await register_command(client, callback_query.message)
    await callback_query.answer("Registration successful!")

@app.on_message(filters.command("register"))
async def register_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        registered_users.add(user_id)
        user_info = (
            "🆕 New User Alert!\n\n"
            f"👤 Name: {message.from_user.first_name}\n"
            f"🔖 Username: @{message.from_user.username}\n"
            f"🆔 ID: {user_id}"
        )
        await client.send_message(ADMIN_ID, user_info)
        
        success_msg = (
            "✅ 𝗥𝗲𝗴𝗶𝘀𝘁𝗿𝗮𝘁𝗶𝗼𝗻 𝗦𝘂𝗰𝗰𝗲𝘀𝘀𝗳𝘂𝗹!\n\n"
            "Welcome to the Gateway Checker Bot!\n\n"
            "📌 Available Commands:\n"
            "• /chk - Check URLs\n"
            "• /txt - Process bulk URLs\n"
            "• /search - Find new URLs\n"
            "• /about - Bot information\n\n"
            "🚀 Ready to start checking!"
        )
        await message.reply(success_msg, reply_to_message_id=message.id)
    else:
        already_reg = (
            "ℹ️ Already Registered\n\n"
            "You're already set up and ready to go!\n"
            "Use /about for more information."
        )
        await message.reply(already_reg, reply_to_message_id=message.id)

@app.on_message(filters.command("search"))
async def search_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply(
            "🔒 Access Required\n\n"
            "Please register first with /register", 
            reply_to_message_id=message.id
        )
        return

    try:
        # Improved command parsing
        args = message.text.split(maxsplit=2)
        if len(args) < 2:
            await message.reply(
                "🔎 Search Guide\n\n"
                "Usage:\n"
                "/search query [amount]\n\n"
                "Examples:\n"
                "• /search payment gateway 10\n"
                "• /search site:example.com 5\n"
                "• /search \"online checkout\"",
                reply_to_message_id=message.id
            )
            return

        # Extract query and amount
        if len(args) == 2:
            query = args[1]
            amount = 10
        else:
            # Check if the last word is a number
            parts = args[2].split()
            if parts[-1].isdigit():
                amount = int(parts[-1])
                query = args[1] + " " + " ".join(parts[:-1])
            else:
                query = args[1] + " " + args[2]
                amount = 10

        # Limit amount to reasonable values
        amount = min(max(amount, 1), 30)

        status_msg = await message.reply(
            "🔍 Searching...\n"
            "Please wait while I find the best URLs.",
            reply_to_message_id=message.id
        )

        # Improved search with better user agent and parameters
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        urls = []
        search_params = {
            'q': query,
            'num': amount,
            'hl': 'en',
            'gl': 'us',
            'safe': 'off',
        }
        
        async with aiohttp.ClientSession() as session:
            for start in range(0, amount, 10):
                search_params['start'] = start
                async with session.get('https://www.google.com/search', params=search_params, headers=headers) as response:
                    if response.status == 200:
                        html_content = await response.text()
                        soup = BeautifulSoup(html_content, 'html.parser')
                        search_results = soup.find_all('div', class_='yuRUbf')
                        
                        for result in search_results:
                            url_tag = result.find('a')
                            if url_tag and 'href' in url_tag.attrs:
                                url = url_tag['href']
                                if url not in urls:
                                    urls.append(url)
                                    if len(urls) >= amount:
                                        break
                    
                    if len(urls) >= amount:
                        break
                
                await asyncio.sleep(1)  # Avoid rate limiting

        if not urls:
            await status_msg.edit(
                "❌ No Results Found\n\n"
                "Try a different search query."
            )
            return

        # Format results with improved styling
        if len(urls) <= 10:
            result_text = (
                "🔍 Search Results\n\n"
                f"Query: {query}\n"
                f"Found: {len(urls)} URLs\n\n"
                "URLs:\n"
            )
            
            for i, url in enumerate(urls, 1):
                result_text += f"{i}. {url}\n"
                
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔍 Check All URLs", callback_data=f"check_all_{message.id}")]
            ])
            
            await status_msg.edit(
                result_text,
                reply_markup=keyboard
            )
        else:
            # Create a text file for bulk results
            file_name = f"search_results_{message.from_user.id}.txt"
            with open(file_name, "w") as f:
                for url in urls:
                    f.write(f"{url}\n")

            # Send the file with improved caption
            await message.reply_document(
                document=file_name,
                caption=(
                    "🔍 Search Results\n\n"
                    f"Query: {query}\n"
                    f"Found: {len(urls)} URLs\n\n"
                    "Reply to this file with /txt to check all URLs."
                ),
                reply_to_message_id=message.id
            )
            os.remove(file_name)
            await status_msg.delete()

    except Exception as e:
        await message.reply(
            f"❌ Error\n\n"
            f"{str(e)}",
            reply_to_message_id=message.id
        )

@app.on_callback_query(filters.regex("^check_all_"))
async def check_all_callback(client, callback_query):
    message_id = int(callback_query.data.split('_')[2])
    message = callback_query.message
    
    # Extract URLs from the message
    urls = []
    for line in message.text.split('\n'):
        if line.strip().startswith(tuple('0123456789')) and '. ' in line:
            url = line.split('. ', 1)[1].strip()
            if url.startswith('http'):
                urls.append(url)
    
    if not urls:
        await callback_query.answer("No URLs found to check!")
        return
    
    await callback_query.answer("Starting gateway check...")
    
    # Create a new message for results
    response = await message.reply(
        "🔍 Checking Gateways...\n"
        "Please wait while I analyze the URLs."
    )
    
    # Process URLs (reuse the chk_command logic)
    results = []
    for url in urls:
        result = await check_gateway(url)
        if "error" in result:
            gateway_info = (
                f"❌ Error Checking\n"
                f"URL: {url}\n"
                f"Error: {result['error']}\n"
                f"Time: {result['response_time']}s\n\n"
            )
        else:
            gateway_info = (
                f"✅ Gateway Check\n"
                f"URL: {url}\n"
                f"Gateways: {', '.join(result['gateways']) if result['gateways'] else 'None'}\n"
                f"Captcha: {'Yes' if result['captcha']['detected'] else 'No'} "
                f"({', '.join(result['captcha']['types']) if result['captcha']['detected'] else 'N/A'})\n"
                f"Cloudflare: {'Yes' if result['cloudflare'] else 'No'}\n"
                f"Security: {', '.join(result['security_features']) if result['security_features'] else 'Basic'}\n"
                f"Status: {result['status_code']} {result['status_icon']}\n"
                f"Time: {result['response_time']}s\n\n"
            )
        
        results.append(gateway_info)
        
        full_message = "🔍 Gateway Check Results\n\n" + "".join(results)
        
        try:
            await response.edit(full_message)
        except Exception:
            # If message is too long, create a new message
            response = await message.reply(full_message)

@app.on_message(filters.command("about"))
async def about_command(client, message: Message):
    about_text = (
        "✨ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 𝗕𝗼𝘁 ✨\n\n"
        "Your ultimate tool for payment gateway detection.\n\n"
        "🚀 Features:\n"
        "• Fast multi-URL checking\n"
        "• Bulk URL processing\n"
        "• Advanced gateway detection\n"
        "• Security analysis\n"
        "• URL search functionality\n\n"
        "💳 Detectable Gateways:\n"
        "Stripe, Braintree, PayPal, Square, Amazon Pay, Klarna, Adyen, "
        "Authorize.net, Worldpay, Cybersource, 2Checkout, WooCommerce\n\n"
        "🛡️ Security Checks:\n"
        "• Captcha systems\n"
        "• Cloudflare protection\n"
        "• Payment security features\n\n"
        "📌 Commands:\n"
        "• /chk - Check URLs (up to 15)\n"
        "• /txt - Process URLs from file\n"
        "• /search - Find new URLs\n\n"
        "🔍 Happy gateway hunting!"
    )
    await message.reply(about_text, reply_to_message_id=message.id)

@app.on_message(filters.command("chk"))
async def chk_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply(
            "🔒 Access Required\n\n"
            "Please register first with /register", 
            reply_to_message_id=message.id
        )
        return

    # Extract URLs from the message
    if message.reply_to_message:
        text = message.reply_to_message.text or message.reply_to_message.caption
    else:
        text = message.text

    # Use regex to find URLs in the text
    urls = re.findall(r'https?://\S+', text)

    if not urls:
        await message.reply(
            "🔍 URL Checker\n\n"
            "Usage:\n"
            "/chk URL1 URL2 ...\n\n"
            "Examples:\n"
            "• /chk https://example.com\n"
            "• /chk https://site1.com https://site2.com",
            reply_to_message_id=message.id
        )
        return

    if len(urls) > 25:
        await message.reply(
            "⚠️ Limit Exceeded\n\n"
            "Maximum 25 URLs allowed at once.\n"
            "For bulk checking, use /txt command.", 
            reply_to_message_id=message.id
        )
        return

    response = await message.reply(
        "🔍 Gateway Checker\n\n"
        "Analyzing URLs... Please wait.", 
        reply_to_message_id=message.id
    )
    
    results = []

    for url in urls:
        result = await check_gateway(url)
        if "error" in result:
            gateway_info = (
                f"❌ Error Checking\n"
                f"URL: {url}\n"
                f"Error: {result['error']}\n"
                f"Time: {result['response_time']}s\n\n"
            )
        else:
            gateway_info = (
                f"✅ Gateway Check\n"
                f"URL: {url}\n"
                f"Gateways: {', '.join(result['gateways']) if result['gateways'] else 'None'}\n"
                f"Captcha: {'Yes' if result['captcha']['detected'] else 'No'} "
                f"({', '.join(result['captcha']['types']) if result['captcha']['detected'] else 'N/A'})\n"
                f"Cloudflare: {'Yes' if result['cloudflare'] else 'No'}\n"
                f"Security: {', '.join(result['security_features']) if result['security_features'] else 'Basic'}\n"
                f"Status: {result['status_code']} {result['status_icon']}\n"
                f"Time: {result['response_time']}s\n\n"
            )
        
        results.append(gateway_info)
        
        full_message = "🔍 Gateway Check Results\n\n" + "".join(results)
        
        try:
            await response.edit(full_message)
        except Exception:
            # If message is too long, create a new message
            response = await message.reply(full_message)

@app.on_message(filters.command("txt") & filters.reply)
async def txt_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply(
            "🔒 Access Required\n\n"
            "Please register first with /register", 
            reply_to_message_id=message.id
        )
        return

    replied_message = message.reply_to_message
    if not replied_message.document or not replied_message.document.file_name.endswith('.txt'):
        await message.reply(
            "📄 Bulk URL Checker\n\n"
            "Usage:\n"
            "1. Upload a .txt file with URLs (one per line)\n"
            "2. Reply to the file with /txt\n\n"
            "Example file content:\n"
            "https://example1.com\n"
            "https://example2.com",
            reply_to_message_id=message.id
        )
        return

    file = await replied_message.download()
    with open(file, 'r') as f:
        urls = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]

    os.remove(file)

    if not urls:
        await message.reply(
            "❌ No Valid URLs\n\n"
            "The file doesn't contain any valid URLs.\n"
            "Make sure each URL starts with http:// or https://", 
            reply_to_message_id=message.id
        )
        return

    total_urls = len(urls)
    response = await message.reply(
        f"📊 Bulk URL Checker\n\n"
        f"Total URLs: {total_urls}\n"
        f"Status: Starting check...\n\n"
        f"This may take some time. Please wait.", 
        reply_to_message_id=message.id
    )

    results = {gateway: [] for gateway in GATEWAYS.keys()}
    checked = 0
    found_gateways = set()

    async def update_message():
        while checked < total_urls:
            await asyncio.sleep(2)
            remaining = total_urls - checked
            progress = int((checked / total_urls) * 20)
            progress_bar = '█' * progress + '░' * (20 - progress)
            percentage = int((checked / total_urls) * 100)
            
            status_lines = [
                f"📊 Bulk URL Checker\n\n"
                f"Progress: [{progress_bar}] {percentage}%\n"
                f"Checked: {checked}/{total_urls}\n"
                f"Remaining: {remaining}\n\n"
            ]
            
            if found_gateways:
                status_lines.append("Gateways Found:\n")
                for gateway in sorted(found_gateways):
                    status_lines.append(f"• {gateway}: {len(results[gateway])}\n")
            
            status = "".join(status_lines)
            try:
                await response.edit(status)
            except Exception:
                pass

    update_task = asyncio.create_task(update_message())

    # Process URLs in batches for better performance
    batch_size = 5
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        tasks = [check_gateway(url) for url in batch]
        batch_results = await asyncio.gather(*tasks)
        
        for url, result in zip(batch, batch_results):
            checked += 1
            if "error" not in result and result["gateways"]:
                for gateway in result["gateways"]:
                    results[gateway].append(url)
                    found_gateways.add(gateway)

    update_task.cancel()

    # Send final results with improved formatting
    for gateway in sorted(found_gateways):
        gateway_urls = results[gateway]
        if gateway_urls:
            # Format URLs in a clean, readable format
            if len(gateway_urls) <= 20:
                url_list = '\n'.join(f"• {url}" for url in gateway_urls)
                result_text = (
                    f"💳 {gateway} Gateways\n\n"
                    f"{url_list}\n\n"
                )
                await message.reply(result_text)
            else:
                # For large results, create a file
                file_name = f"{gateway.lower().replace(' ', '_')}_{message.from_user.id}.txt"
                with open(file_name, "w") as f:
                    for url in gateway_urls:
                        f.write(f"{url}\n")
                
                await message.reply_document(
                    document=file_name,
                    caption=(
                        f"💳 {gateway} Gateways\n\n"
                        f"Total: {len(gateway_urls)} URLs"
                    )
                )
                os.remove(file_name)

    # Send final summary
    final_status = (
        "✅ Bulk Check Complete\n\n"
        f"Total URLs: {total_urls}\n\n"
    )

    if found_gateways:
        final_status += "Gateway Summary:\n"
        for gateway in sorted(found_gateways):
            final_status += f"• {gateway}: {len(results[gateway])}\n"
    else:
        final_status += "No payment gateways found in the provided URLs."

    await response.edit(final_status)

# Create a simple web server for Render
async def handle(request):
    return web.Response(text="Gateway Checker Bot is running!", content_type="text/html")

# Setup the web app
web_app = web.Application()
web_app.router.add_get('/', handle)

# Function to run the web server
async def run_web_server():
    runner = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    print(f"Web server started on port {PORT}")

# Function to run the bot
async def run_bot():
    await app.start()
    print("Bot started")
    await asyncio.Event().wait()  # Run forever

# Main function to run both the web server and the bot
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    
    # Run both the web server and the  == "__main__":
    loop = asyncio.get_event_loop()
    
    # Run both the web server and the bot
    loop.create_task(run_web_server())
    loop.create_task(run_bot())
    
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(app.stop())
        loop.close()
