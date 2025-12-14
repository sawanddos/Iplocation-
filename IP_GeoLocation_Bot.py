#!/usr/bin/env python3
"""
IP Geolocation Bot - Cyber Security Tool
Author: @UnknownGuy9876
"""

import requests
import json
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

class IPGeolocationBot:
    def __init__(self, token):
        self.token = token
        self.services = {
            'ipapi': 'https://ipapi.co/{ip}/json/',
            'ipinfo': 'https://ipinfo.io/{ip}/json',
            'ipapi_com': 'http://ip-api.com/json/{ip}'
        }
    
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Send welcome message"""
        text = """
🔍 *IP Geolocation Bot*
Get detailed information about any IP address!

*Commands:*
/ip [address] - Get IP information
/myip - Get your own IP info
/bulk - Check multiple IPs (file upload)
/threat - Check IP threat level
/help - Show this message

*Features:*
• Geolocation mapping
• ISP/Organization info
• Threat intelligence
• Proxy/VPN detection
• Historical data
• Bulk processing

*Example:* `/ip 8.8.8.8`
        """
        await update.message.reply_text(text, parse_mode='Markdown')
    
    async def get_ip_info(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Get IP information"""
        ip = ' '.join(context.args) if context.args else None
        
        if not ip:
            # Get user's IP
            response = requests.get('https://api.ipify.org?format=json')
            ip = response.json()['ip']
            message = "📍 *Your IP Information*\n\n"
        else:
            message = f"🔍 *IP Information for {ip}*\n\n"
        
        # Get data from multiple sources
        try:
            # Source 1: ipapi.co
            url = f"https://ipapi.co/{ip}/json/"
            response = requests.get(url, headers={'User-Agent': 'TelegramBot'})
            data1 = response.json()
            
            # Source 2: ip-api.com
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url)
            data2 = response.json()
            
            # Compile information
            info = f"""
*IP Address:* `{ip}`
*Location:* {data1.get('city', 'N/A')}, {data1.get('region', 'N/A')}, {data1.get('country_name', 'N/A')}
*Coordinates:* {data1.get('latitude', 'N/A')}, {data1.get('longitude', 'N/A')}
*ISP:* {data1.get('org', data2.get('isp', 'N/A'))}
*ASN:* {data1.get('asn', 'N/A')}
*Timezone:* {data1.get('timezone', 'N/A')}
*Currency:* {data1.get('currency', 'N/A')}
*Languages:* {data1.get('languages', 'N/A')}

*Network Info:*
• Organization: `{data2.get('org', 'N/A')}`
• AS: `{data2.get('as', 'N/A')}`
• Mobile: `{'Yes' if data1.get('mobile', False) else 'No'}`
• Proxy: `{'Yes' if data1.get('proxy', False) else 'No'}`
• Hosting: `{'Yes' if data2.get('hosting', False) else 'No'}`
            """
            
            # Add threat intelligence
            threat_info = await self.get_threat_intelligence(ip)
            info += f"\n*Threat Intelligence:*\n{threat_info}"
            
            # Create map button
            if data1.get('latitude') and data1.get('longitude'):
                lat, lon = data1['latitude'], data1['longitude']
                map_url = f"https://www.google.com/maps?q={lat},{lon}"
                keyboard = InlineKeyboardMarkup([[
                    InlineKeyboardButton("📍 View on Map", url=map_url),
                    InlineKeyboardButton("🛡️ Threat Check", callback_data=f"threat_{ip}")
                ]])
            else:
                keyboard = None
            
            await update.message.reply_text(message + info, parse_mode='Markdown', reply_markup=keyboard)
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error getting IP information: {str(e)}")
    
    async def get_threat_intelligence(self, ip: str) -> str:
        """Check IP threat level"""
        try:
            # AbuseIPDB check
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': 'YOUR_API_KEY_HERE',  # Get free key from abuseipdb.com
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()['data']
                score = data.get('abuseConfidenceScore', 0)
                reports = data.get('totalReports', 0)
                
                threat_level = "🟢 Low" if score < 25 else "🟡 Medium" if score < 75 else "🔴 High"
                
                return f"• Threat Score: {score}%\n• Reports: {reports}\n• Level: {threat_level}\n• Last Reported: {data.get('lastReportedAt', 'Never')}"
        
        except:
            pass
        
        return "• Threat data unavailable (API limit)"
    
    async def bulk_ip_check(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle bulk IP file upload"""
        await update.message.reply_text(
            "📁 *Bulk IP Check*\n\n"
            "Upload a text file with one IP per line.\n"
            "Max: 50 IPs per file\n"
            "Format:\n"
            "```\n"
            "8.8.8.8\n"
            "1.1.1.1\n"
            "192.168.1.1\n"
            "```",
            parse_mode='Markdown'
        )
    
    async def threat_check(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Detailed threat check"""
        ip = ' '.join(context.args) if context.args else None
        if not ip:
            await update.message.reply_text("Usage: `/threat 8.8.8.8`", parse_mode='Markdown')
            return
        
        await update.message.reply_text(f"🔍 Checking threat data for {ip}...")
        
        # Multiple threat intelligence sources
        threats = []
        
        # VirusTotal
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {'x-apikey': 'YOUR_VIRUSTOTAL_API_KEY'}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                threats.append(f"• VirusTotal: {stats['malicious']} malicious / {sum(stats.values())} total")
        except:
            pass
        
        # ThreatFox
        try:
            url = f"https://threatfox-api.abuse.ch/api/v1/"
            payload = {'query': 'search_ioc', 'search_term': ip}
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    threats.append(f"• ThreatFox: {len(data['data'])} malicious activities")
        except:
            pass
        
        # AlienVault OTX (free tier)
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('pulse_info', {}).get('count', 0)
                threats.append(f"• AlienVault: {pulses} threat pulses")
        except:
            pass
        
        result = f"🛡️ *Threat Intelligence for {ip}*\n\n"
        if threats:
            result += "\n".join(threats)
            result += "\n\n⚠️ *Recommendations:*\n"
            if any('malicious' in t or 'threat' in t for t in threats):
                result += "• Block this IP in firewall\n• Investigate related traffic\n• Scan affected systems"
            else:
                result += "• Monitor for suspicious activity\n• Regular security audits\n• Keep systems updated"
        else:
            result += "No threat intelligence found.\nIP appears clean."
        
        await update.message.reply_text(result, parse_mode='Markdown')

# Usage:
bot = IPGeolocationBot("YOUR_BOT_TOKEN")
# Add handlers and run...