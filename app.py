import asyncio
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=3939412237&password=74C35008C7E8BE5B618F6B482EC73D840F863E2AF750C1317CA66D4CD74F19FB"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3939493997&password=D08775EC0CCCEA77B2426EBC4CF04C097E0D58822804756C02738BF37578EE17"
    else:
        return "uid=3939507748&password=55A6E86C5A338D133BAD02964EFB905C7C35A86440496BC210A682146DCE9F32"

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
               'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    region = region.upper()
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
    async with httpx.AsyncClient() as client:
        resp = await client.post(server+endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# === Caching Decorator ===
def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Custom JSON Formatter ===
def format_protobuf_response(data):
    """
    Format the protobuf response to match the desired JSON structure
    """
    formatted_data = {}
    
    # Basic Info
    if 'basicInfo' in data:
        basic_info = data['basicInfo']
        formatted_data['basicInfo'] = {
            'accountId': basic_info.get('accountId', ''),
            'accountPrefers': basic_info.get('accountPrefers', {}),
            'accountType': basic_info.get('accountType', 0),
            'badgeCnt': basic_info.get('badgeCnt', 0),
            'badgeId': basic_info.get('badgeId', 0),
            'bannerId': basic_info.get('bannerId', 0),
            'createAt': basic_info.get('createAt', ''),
            'csMaxRank': basic_info.get('csMaxRank', 0),
            'csRank': basic_info.get('csRank', 0),
            'csRankingPoints': basic_info.get('csRankingPoints', 0),
            'exp': basic_info.get('exp', 0),
            'externalIconInfo': basic_info.get('externalIconInfo', {}),
            'hasElitePass': basic_info.get('hasElitePass', False),
            'headPic': basic_info.get('headPic', 0),
            'lastLoginAt': basic_info.get('lastLoginAt', ''),
            'level': basic_info.get('level', 0),
            'liked': basic_info.get('liked', 0),
            'maxRank': basic_info.get('maxRank', 0),
            'nickname': basic_info.get('nickname', ''),
            'rank': basic_info.get('rank', 0),
            'rankingPoints': basic_info.get('rankingPoints', 0),
            'region': basic_info.get('region', ''),
            'releaseVersion': basic_info.get('releaseVersion', ''),
            'role': basic_info.get('role', 0),
            'seasonId': basic_info.get('seasonId', 0),
            'showBrRank': basic_info.get('showBrRank', False),
            'showCsRank': basic_info.get('showCsRank', False),
            'socialHighLightsWithBasicInfo': basic_info.get('socialHighLightsWithBasicInfo', {}),
            'title': basic_info.get('title', 0),
            'weaponSkinShows': basic_info.get('weaponSkinShows', []),
            # ✅ Prime related fields
            'primeLevel': basic_info.get('primeLevel', 'PRIME_LEVEL_NONE'),
            'primeExpireTime': basic_info.get('primeExpireTime', 0),
            'primePoints': basic_info.get('primePoints', 0),
            'primeSeasonProgress': basic_info.get('primeSeasonProgress', 0)
        }
    
    # Captain Basic Info
    if 'captainBasicInfo' in data:
        captain_info = data['captainBasicInfo']
        formatted_data['captainBasicInfo'] = {
            'accountId': captain_info.get('accountId', ''),
            'accountPrefers': captain_info.get('accountPrefers', {}),
            'accountType': captain_info.get('accountType', 0),
            'badgeCnt': captain_info.get('badgeCnt', 0),
            'badgeId': captain_info.get('badgeId', 0),
            'bannerId': captain_info.get('bannerId', 0),
            'createAt': captain_info.get('createAt', ''),
            'csMaxRank': captain_info.get('csMaxRank', 0),
            'csRank': captain_info.get('csRank', 0),
            'csRankingPoints': captain_info.get('csRankingPoints', 0),
            'exp': captain_info.get('exp', 0),
            'externalIconInfo': captain_info.get('externalIconInfo', {}),
            'hasElitePass': captain_info.get('hasElitePass', False),
            'headPic': captain_info.get('headPic', 0),
            'lastLoginAt': captain_info.get('lastLoginAt', ''),
            'level': captain_info.get('level', 0),
            'liked': captain_info.get('liked', 0),
            'maxRank': captain_info.get('maxRank', 0),
            'nickname': captain_info.get('nickname', ''),
            'rank': captain_info.get('rank', 0),
            'rankingPoints': captain_info.get('rankingPoints', 0),
            'region': captain_info.get('region', ''),
            'releaseVersion': captain_info.get('releaseVersion', ''),
            'role': captain_info.get('role', 0),
            'seasonId': captain_info.get('seasonId', 0),
            'showBrRank': captain_info.get('showBrRank', False),
            'showCsRank': captain_info.get('showCsRank', False),
            'socialHighLightsWithBasicInfo': captain_info.get('socialHighLightsWithBasicInfo', {}),
            'title': captain_info.get('title', 0),
            'weaponSkinShows': captain_info.get('weaponSkinShows', []),
            # ✅ Prime related fields
            'primeLevel': captain_info.get('primeLevel', 'PRIME_LEVEL_NONE'),
            'primeExpireTime': captain_info.get('primeExpireTime', 0),
            'primePoints': captain_info.get('primePoints', 0),
            'primeSeasonProgress': captain_info.get('primeSeasonProgress', 0)
        }
    
    # Clan Basic Info
    if 'clanBasicInfo' in data:
        clan_info = data['clanBasicInfo']
        formatted_data['clanBasicInfo'] = {
            'capacity': clan_info.get('capacity', 0),
            'captainId': clan_info.get('captainId', ''),
            'clanId': clan_info.get('clanId', ''),
            'clanLevel': clan_info.get('clanLevel', 0),
            'clanName': clan_info.get('clanName', ''),
            'memberNum': clan_info.get('memberNum', 0)
        }
    
    # Credit Score Info
    if 'creditScoreInfo' in data:
        credit_info = data['creditScoreInfo']
        formatted_data['creditScoreInfo'] = {
            'creditScore': credit_info.get('creditScore', 0),
            'periodicSummaryEndTime': credit_info.get('periodicSummaryEndTime', ''),
            'rewardState': credit_info.get('rewardState', 'REWARD_STATE_UNCLAIMED')
        }
    
    # Diamond Cost Res
    if 'diamondCostRes' in data:
        diamond_info = data['diamondCostRes']
        formatted_data['diamondCostRes'] = {
            'diamondCost': diamond_info.get('diamondCost', 0)
        }
    
    # Pet Info
    if 'petInfo' in data:
        pet_info = data['petInfo']
        formatted_data['petInfo'] = {
            'exp': pet_info.get('exp', 0),
            'id': pet_info.get('id', 0),
            'isSelected': pet_info.get('isSelected', False),
            'level': pet_info.get('level', 0),
            'name': pet_info.get('name', ''),
            'selectedSkillId': pet_info.get('selectedSkillId', 0),
            'skinId': pet_info.get('skinId', 0)
        }
    
    # Profile Info
    if 'profileInfo' in data:
        profile_info = data['profileInfo']
        formatted_data['profileInfo'] = {
            'avatarId': profile_info.get('avatarId', 0),
            'clothes': profile_info.get('clothes', []),
            'equipedSkills': profile_info.get('equipedSkills', []),
            'isSelected': profile_info.get('isSelected', False),
            'isSelectedAwaken': profile_info.get('isSelectedAwaken', False),
            'skinColor': profile_info.get('skinColor', 0)
        }
    
    # Social Info
    if 'socialInfo' in data:
        social_info = data['socialInfo']
        formatted_data['socialInfo'] = {
            'accountId': social_info.get('accountId', ''),
            'language': social_info.get('language', 'Language_EN'),
            'modePrefer': social_info.get('modePrefer', 'ModePrefer_BR'),
            'rankShow': social_info.get('rankShow', 'RankShow_CS'),
            'signature': social_info.get('signature', '')
        }
    
    # Add credit field
    formatted_data['credit'] = '@Ujjaiwal'
    
    return formatted_data

# === Flask Routes ===
@app.route('/player-info')
@cached_endpoint()
def get_account_info():
    region = request.args.get('region')
    uid = request.args.get('uid')

    # Pehle basic validation
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    if not region:
        return jsonify({"error": "Please provide REGION."}), 400

    try:
        # API call
        return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        
        # Format the response with the new structure
        formatted_data = format_protobuf_response(return_data)

        # Agar data mila toh usko beautify karke bhejo
        formatted_json = json.dumps(formatted_data, indent=2, ensure_ascii=False)
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}

    except Exception as e:
        # Agar koi error aaye toh yeh catch karega
        return jsonify({"error": "Invalid UID or Region. Please check and try again."}), 500

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

# === Startup ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)