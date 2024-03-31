from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib.auth.models import User
from django.contrib import auth
from django.urls import reverse_lazy
from django.contrib.auth.hashers import make_password
import secrets
from django.http import JsonResponse, HttpResponse
from eth_account.messages import encode_defunct
import web3
from web3.auto import w3
from web3 import Web3
import json
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.conf import settings
import hashlib
from datetime import datetime as date_2
from collections import OrderedDict
import urllib
from django.utils.decorators import method_decorator


#  Outline ->  Basic Info / Homepage / 登入註冊 / 平台幣 /  拍賣 + 直接販賣[創建 NFT 721 and 1155 / 拍賣區 / 直接販賣] / 個人資料 / 前端呼叫 DB

#  Basic Info
# platform account
platform_address = {
    'private_address': '6d55432d5c011cdcf02b4e8de5e54e397f02bbd4151dd59466e9f7801df2eda9',
    'public_address': '0xAa6043be61544D39E3C0c4FEf9d0644e164188A1',
}
# Infura Node
url = "https://goerli.infura.io/v3/a2952fa5268f491cb8b3bbac641ecac0"
# Initiating Web3
web3 = Web3(web3.HTTPProvider(url))

# Homepage =============
# 相關 class : Index
# 相關 function : 無
class Index(View):
    def get(self, request, *args, **kwargs):
        user_address = request.user
        user_address = str(user_address)
        # call_ERC865(user_address)
        from .forms import Create721Form, Create1155Form,CreateAuctionForm,Create_direct_saleForm
        create721form = Create721Form(initial={'user_address': user_address})
        create1155form = Create1155Form(initial={'user_address': user_address})
        createAuctionForm = CreateAuctionForm(initial={'seller_addr': user_address})
        create_direct_saleForm = Create_direct_saleForm(initial={'seller_addr': user_address})
        context = {'create721form':create721form, 'create1155form':create1155form,'createAuctionForm':createAuctionForm,'create_direct_saleForm':create_direct_saleForm }
        return render(request, 'app/index.html',context)

# 登入註冊 =============
# 相關 class : Login / Logout
# 相關 function : signNonce / checkSignature
# 登入
class Login(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'app/login.html')

    def post(self, request, *args, **kwargs):
        account = request.POST.get('account')
        signature = request.POST.get('signature')
        message = request.POST.get('message')
        if(account != ""):
            try:
                user = User.objects.get(username=account)
            except User.DoesNotExist:
                user = None
            if user:
                    if(checkSignature(signature, message) == account):
                        user.backend = 'django.contrib.auth.backends.ModelBackend'
                        auth.login(request, user)
                        return redirect(reverse_lazy('settings721'))
                    else:
                        context = {
                            'addr': account,
                            'recover':(signature,message),
                        }
                        return render(request, 'app/login.html', context)
            else:
                User.objects.create(
                    username = account,
                    password = make_password(secrets.token_hex(32)),
                )
                user.backend = 'django.contrib.auth.backends.ModelBackend'
                auth.login(request, user)
                return redirect(reverse_lazy('settings721'))
        return render(request, 'app/login.html')

# 傳給前端 function getNonce()
def signNonce(request):
    nonce = secrets.token_hex(32)
    return JsonResponse({'nonce':nonce})

# Check 簽署
def checkSignature(signature, message):
    message_hash = encode_defunct(text=message)
    address = web3.eth.account.recover_message(message_hash, signature=signature)
    return address

# 登出
class Logout(View):
    def get(request):
        auth.logout(request)
        return redirect(reverse_lazy('login'))


# 平台幣 =============
# 相關 class : Create_erc865 / Logout / PaymentReturnView
# 相關 function : signNonce / sign_res / buyERC865 / createCheckValue / getAbiBytecode / checkSignature / transferToPlatform / transferFromPlatform / call_ERC865
from app.contract.bytecode.erc865_abi import erc865_abi
from app.contract.bytecode.erc865_bytecode import erc865_bytecode
from web3 import Web3
w3 = Web3(web3.HTTPProvider("https://goerli.infura.io/v3/a2952fa5268f491cb8b3bbac641ecac0"))
erc865_contract_address = '0x16370f5ad5e1fbda8d77147c03e709a55b3ab176'
DECIMALS = 10**18
# Create 865 Page
class Create_erc865(View):
        def get(self, request, *args, **kwargs):
            from .models import User as user_2
            user_address = request.user
            user_address = str(user_address)
            print(user_address)
            total_balance = call_ERC865(user_address)
            print(total_balance)
            user_2 = user_2.objects.filter(public_address=user_address).first()
            context = {'User': user_2}
            return render(request,'app/create865.html', context)

# 傳給前端 function getNonce()
def signNonce(request):
    nonce = secrets.token_hex(32)
    return JsonResponse({'nonce':nonce})

# 簽名授權
@csrf_exempt
def sign_res(request):
    nonce = True
    return JsonResponse({'nonce':nonce})

# 進入綠界
@csrf_exempt
def buyERC865(request):
    context = {}
    if request.method == 'GET':
        amount =  request.GET.get('ERC_amount')
        address = request.GET.get('address')
        ERC_address =  request.GET.get('ERC_address')
        # print(f'ERC amount {amount}\naddress {address}\nERC_address: {ERC_address}')
        payment_data = {
            # === 必填欄位 ===
            # 付款資訊
            "MerchantID": settings.ECPAY_MERCHEAT_ID,
            "ReturnURL": "http://127.0.0.1:8000/payment/backend/return/",
            "ChoosePayment": "ALL",
            "PaymentType": "aio",
            
            # 訂單資訊
            "MerchantTradeNo": hashlib.md5(str(date_2.now()).encode()).hexdigest()[0:20], # 訂單號
            "MerchantTradeDate": date_2.now().strftime("%Y/%m/%d %H:%M:%S"), # 訂單建立日期
            
            
            # 商品資訊
            "TotalAmount": request.GET.get('ERC_amount'),
            "TradeDesc": "ecapy 購物商城",
            "ItemName": "林奕辰的engine",


            # === 選填欄位 ===
            "CustomField1": str(request.user),
            "CustomField2": request.GET.get('ERC_address'),
            "OrderResultURL": "http://127.0.0.1:8000/frontend/return/", # 用這個 view 接結果
        }
        # print(payment_data)
        # 檢查碼機制，參考 15.檢查碼機制
        payment_data["CheckMacValue"] = createCheckValue(payment_data)
        context.update({
            "ECPAY_API_URL": settings.ECPAY_API_URL,
            "formData": payment_data,
        })
        # print(context)
        # return render(request, "hello_world.html", context)
        # return JsonResponse(context)
        return HttpResponse(json.dumps(context), content_type="application/json")

# 檢查碼演算法
def createCheckValue(data):
    data = OrderedDict(data)
    data = OrderedDict(sorted(data.items()))

    orderedDict = OrderedDict()
    orderedDict['HashKey'] = settings.ECPAY_API_HASH_KEY
    for field in data:
        orderedDict[field] = data[field]
    orderedDict['HashIV'] = settings.ECPAY_API_HASH_IV

    dataList = []
    for k, v in orderedDict.items():
        dataList.append("%s=%s" % (k, v))
    dataStr = u"&".join(dataList)
    
    
    encodeStr = urllib.parse.urlencode({'data': dataStr,})[5:]
    checkValue = hashlib.md5(encodeStr.lower().encode()).hexdigest().upper()

    return checkValue

@csrf_exempt
def getAbiBytecode(request):
    context = {'erc865_abi':erc865_abi, 'erc865_contract_addr':erc865_contract_address,'erc865_bytecode':erc865_bytecode}
    return HttpResponse(json.dumps(context), content_type="application/json")

# 回傳綠界結果
@method_decorator(csrf_exempt, name='dispatch')        
class PaymentReturnView(View):
    def post(self, request, *args, **kwargs):
        context = {}
        # request.POST 就是由綠界回傳的付款結果
        res = request.POST.dict()
        # 根據付款結果做後續處理，EX: 設定訂單為已付款、付款失敗時的處理...等等
        erc_address = w3.toChecksumAddress(res['CustomField2'])
        to_address = w3.toChecksumAddress(res['CustomField1'])
        amount = int(res['TradeAmt'])*DECIMALS
        # web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        erc865_contract_address = Web3.toChecksumAddress('0x16370f5ad5e1fbda8d77147c03e709a55b3ab176')
        erc865Contract = w3.eth.contract(address=erc865_contract_address, abi=erc865_abi)
        # make transaction
        transaction = erc865Contract.functions.transferFromPlatform(to_address, amount).buildTransaction({  # 測試帳號，將erc20發給他
            'gas':700000,
            'chainId': 4,
            'gasPrice': web3.eth.gas_price,
            'from': platform_address['public_address'],
            'nonce' : web3.eth.get_transaction_count('0xAa6043be61544D39E3C0c4FEf9d0644e164188A1'),
        })
        signed_tx = w3.eth.account.signTransaction(transaction,  platform_address['private_address'])
        # get transaction receipt
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash ,timeout=600)
        logs = erc865Contract.events.Transfer().processReceipt(tx_receipt)
        txhash = tx_receipt['transactionHash'].hex()
        user_address = str(to_address)
        call_ERC865(user_address)
        content = {"txhash":txhash,'res':res} ##顯示到前端
        return render(request, 'app/tx_result.html', content)


# Operations of ERC 865

# account_from -> platform address
def transferToPlatform(_from, _value, _fee):
    _value = int(_value)
    _value = int(_value*DECIMALS)
    _fee = int(_fee*(10**17))
    _from = Web3.toChecksumAddress(_from)
    erc865Contract = w3.eth.contract(address=erc865_contract_address, abi=erc865_abi)
    transaction = erc865Contract.functions.transferToPlatform(_from, _value, _fee).buildTransaction({
        'from': platform_address['public_address'],
        'nonce': w3.eth.getTransactionCount(platform_address['public_address']),
        'gasPrice' : web3.eth.gas_price,
    })
    signed_tx = w3.eth.account.signTransaction(transaction,  platform_address['private_address'])
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    transhash = tx_receipt['transactionHash'].hex()
    receipt_url = "https://goerli.etherscan.io/tx/"+transhash
    print(f'{_from}交易給平台url{receipt_url}')
    #logs = erc865Contract.events.Transfer().processReceipt(tx_receipt)
    #transfer_event = logs[0]['args']
    balance_1 = call_ERC865(_from)
    balance_2 = call_ERC865(platform_address['public_address'])
    print(f'{_from}:{balance_1},平台持有平台幣:{balance_2}')
    return receipt_url

# transferFromPlatform
# 平台轉到 _to address、_value : 1 * 10^18 = 1 平台幣
def transferFromPlatform(_to, _value):
    _value = int(_value * DECIMALS)
    _from = Web3.toChecksumAddress(_from)
    erc865Contract = w3.eth.contract(address=erc865_contract_address, abi=erc865_abi)
    transaction = erc865Contract.functions.transferFromPlatform(_to, _value).buildTransaction({
        'from': platform_address['public_address'],
        'nonce': w3.eth.getTransactionCount(platform_address['public_address']),
        'gasPrice' : web3.eth.gas_price,
    })
    signed_tx = w3.eth.account.signTransaction(transaction,  platform_address['private_address'])
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    transhash = tx_receipt['transactionHash'].hex()
    receipt_url = "https://goerli.etherscan.io/tx/"+transhash
    print(f'平台交易給{_to}url{receipt_url}')
    balance_1 = call_ERC865(_to)
    balance_2 = call_ERC865(platform_address['public_address'])
    print(f'{_to}:{balance_1},平台持有平台幣:{balance_2}')
    return tx_receipt

# balanceOf
def call_ERC865(_user_address):
    # 呼叫 contract balanceOf function -> 結果 update 到 DB -> 回傳值
    from .models import User as user_2
    from django.contrib.auth.models import User
    #  update public_address 沒有做這個一開始就會是空的
    #  if user_address can't find -> update or do the rest stuff
    user_obj = User.objects.filter(username=_user_address).first()
    flag = user_2.objects.filter(user_name=user_obj,public_address=_user_address).count()
    if (flag==0):
        # empty -> update address -> execute rest of the functions
        user_obj = User.objects.filter(username=_user_address).first()
        user_2.objects.create(user_name_id=user_obj.id,user_name=user_obj, public_address=_user_address)
    erc865_contract_address = Web3.toChecksumAddress('0x16370f5ad5e1fbda8d77147c03e709a55b3ab176')
    erc865Contract = w3.eth.contract(address = erc865_contract_address,abi=erc865_abi)
    _user_address = Web3.toChecksumAddress(_user_address)
    ERC865_balance = erc865Contract.functions.balanceOf(_user_address).call()
    ERC865_balance = float(ERC865_balance / DECIMALS)
    user_2.objects.filter(public_address=_user_address).update(platform_token=ERC865_balance)
    return ERC865_balance



# 拍賣 + 直接販賣 =============
# 創建 NFT 721 and 1155 
# 相關 class : Create_NFT / Create_NFT721 / Create_NFT1155 /  Create_NFT_Result
# 相關 function : call_ERC721_balanceOF / call_ERC721_walletOfOwner / ERC721_safe_transfer / call_ERC721_token_ownerOF / call_ERC1155_balanceOF / ERC1155_safe_transfer
from .forms import Create721Form, Create1155Form
from app.contract.bytecode.erc721_abi import erc721_abi
from app.contract.bytecode.erc721_bytecode import erc721_bytecode
from .models import ERC721
import numpy as np
erc721_contract_address = '0xc67aa8e56a28f25c4b4b20ba65df006e9800bce3'

# Create_NFT
class Create_NFT(View):
        def get(self, request, *args, **kwargs):
            return render(request,'app/create_nft.html')
        def post(self, request, *args, **kwargs):
            return render(request,'app/create_nft.html' )

# Create 721
class Create_NFT721(View):
        def get(self, request, *args, **kwargs):
            from .models import User, ERC721, ERC1155 
            user_address = request.user
            user = User.objects.filter(public_address=user_address).first()
            create721form = Create721Form(initial={'user_address': user_address})
            context = {'user':user, 'form': create721form}
            return render(request,'app/create721.html', context)

        # 接收資料 -> 發 NFT、 存入 DB
        def post(self, request, *args, **kwargs):
            context = {'Receipt':''}
            form = Create721Form(request.POST, request.FILES)
            print(f'form{form}')
            # 存入 DB -> (721 Deploy -> mint 1 token ) -> 回傳 etherscan url
            if form.is_valid():
                form.save()
                print(form.cleaned_data['img'])
                _to =  request.user  #收到NFT的address
                _to = str(_to)
                erc721_name = request.POST.get('erc721_name')
                symbol = request.POST.get('symbol')
                # Deploy NFT 721 
                # print(f' Deploy NFT 721 ')
                # NFT = web3.eth.contract(abi=erc721_abi, bytecode=erc721_bytecode)
                # construct_txn = NFT.constructor().buildTransaction(
                #     {
                #         'from': platform_address['public_address'],
                #         'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                #         'gasPrice': web3.eth.gas_price,
                #     }
                # )
                # print(f' Deploy NFT 721 ')
                # tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address']) # 簽名
                # tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)  # transaction送出並且等待回傳
                # tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
                # print(f'tx_receipt{tx_receipt}')
                # contract_address = tx_receipt['contractAddress']
                # transhash = tx_receipt['transactionHash'].hex()
                # receipt_url = "https://goerli.etherscan.io/tx/"+transhash
                # print(receipt_url)
                # print(f'receipt_url{receipt_url}')
                # _mintAmount = int(1) #要創造多少個 
                # ERC721.objects.filter(user_address=_to).update(etherscan_url=receipt_url)
                # ERC721.objects.filter(user_address=_to).update(contract_address=contract_address)
                # context['Receipt']=receipt_url
                # Mint ERC721 token 1 
                #  Create Contract instance
                # print(f'web3.eth.contract(abi=erc721_abi,address=contract_address) {contract_address}')
                # NFT = web3.eth.contract(abi=erc721_abi,address=contract_address)
                # construct_txn = NFT.functions.mint(_to , _mintAmount).buildTransaction(
                #     {
                #         'from': platform_address['public_address'],
                #         'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                        # 'from': _to,
                        # 'nonce': web3.eth.getTransactionCount(_to),
                        # 'gasPrice': web3.eth.gas_price,
                        # }
                    # )
                # print('NFT.functions.mint(_to={_to} , _mintAmount={_mintAmount}).buildTransaction')
                # tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address']) # 簽名
                # print(f'tx_create{tx_create}')
                # tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction) # transaction送出並且等待回傳
                # print(f'tx_hash{tx_hash}')
                # tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
                # print(f'tx_receipt{tx_receipt}')
                # transhash = tx_receipt['transactionHash'].hex()
                # print(f'transhash{transhash}')
                # receipt_url = "https://goerli.etherscan.io/tx/"+transhash
                # print(f'receipt_url{receipt_url}')
                # owner_pre = call_ERC721_token_ownerOF(5, contract_address)
                # print(f'owner_pre {owner_pre}')
                # ERC721_safe_transfer(platform_address['public_address'] , _to , 5 , contract_address)
                # owner_after = call_ERC721_token_ownerOF(5, contract_address)
                # print(f'owner_after{owner_after}')
                # update token id as 
                # erc721_obj = ERC721.objects.filter(user_address=_to).last('id')
                # ERC721.objects.filter(id=erc721_obj.id,user_address=_to).update(erc721_id=erc721_obj.id)
                return render(request,'app/create_nft_result.html',context) # context 回傳發布的合約 url ，且已經有鑄造一個 NFT
            return render(request,'app/create_nft_result.html',context)


# NFT 721 Operations -> Contract : 查詢 Owner、Transfer，DB Update Data ?
def call_ERC721_balanceOF(owner, contract_address):
    owner = Web3.toChecksumAddress(owner)
    ERC721_contract = web3.eth.contract(abi=erc721_abi,address=contract_address)
    ERC721_balance = ERC721_contract.functions.balanceOf(owner).call()
    print("balance :" , ERC721_balance)
    return ERC721_balance


# 有多少 NFT
def call_ERC721_walletOfOwner(_owner , contract_address):
    _owner = Web3.toChecksumAddress(_owner)
    ERC721_contract = web3.eth.contract(abi=erc721_abi,address=contract_address)
    ERC721_walletOfOwner = ERC721_contract.functions.walletOfOwner(_owner).call()
    print("You have the NFT Token ID has :" , ERC721_walletOfOwner)
    return ERC721_walletOfOwner


# _from -> 送出 NFT 的 address，_to -> 收到NFT的address
def ERC721_safe_transfer(_from , _to , _tokenid , contract_address):
    from .models import ERC721
    # Update DB Owner
    ERC721.objects.filter(user_address=_from).update(user_address=_to)
    # _tokenid = 5
    # NFT = web3.eth.contract(abi=erc721_abi, address=contract_address)
    # construct_txn = NFT.functions.safeTransferFrom(_from, _to , _tokenid).buildTransaction(
    #     {
    #         'from': platform_address['public_address'],
    #         'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
    #         'gasPrice': web3.eth.gas_price,
    #     }
    # )
    # tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address']) 
    # tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction) # transaction送出並且等待回傳
    # tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    # transhash = tx_receipt['transactionHash'].hex()
    # print('txn_receipt')
    # recepit_url = "https://goerli.etherscan.io/tx/"+transhash
    # print(recepit_url)
    return 0


# 查 token 的擁有者
def call_ERC721_token_ownerOF(tokenid, contract_address):
    # owner = "0x6d2eb5f96b5A02cc6F01Ed731C24C011b59EA039"
    # owner = Web3.toChecksumAddress(owner)
    ERC721_contract = web3.eth.contract(abi=erc721_abi,address=contract_address)
    ERC721_balance = ERC721_contract.functions.ownerOf(tokenid).call()
    print("ownerOF :" , ERC721_balance)
    return ERC721_balance

# Create 1155
# Problem: 如果 RealArt 呼叫兩次、DB會創建兩筆資料，如有已經創建1155要做甚麼 ?
# get request -> 顯示使用者持有的 erc1155
# post request -> + amount  
from app.contract.bytecode.erc1155_abi import erc1155_abi
contract_erc1155_address = web3.toChecksumAddress("0x260D788D35AfCaA8A3a924625e85cce2ABAD840c")
class Create_NFT1155(View):    
        def get(self, request, *args, **kwargs):
            # 傳入 user 持有的 NFT
            context = {'form':'', 'erc721':'','Message':"", 'user':""}
            from .models import ERC721, User
            user_address = request.user
            user = User.objects.filter(public_address=user_address).first()
            erc721 = ERC721.objects.filter(user_address=user_address)
            context['erc721s'] = erc721
            # 傳入 form
            create1155form = Create1155Form(initial={'user_address': user_address})
            context['form'] = create1155form
            context['user'] = user
            return render(request,'app/create1155.html', context)
        
        def post(self, request, *args, **kwargs):
            # 確認 user 是否有此 erc721 id 沒有就 render create1155.html 該頁面
            form = Create1155Form(request.POST)
            from .models import ERC721
            user_address = request.user
            ERC721_id = request.POST.get('erc721_id')
            erc721 = ERC721.objects.filter(user_address=user_address,erc721_id=ERC721_id).count()
            if erc721 == 0:
                context = {'form':'', 'erc721':'','Message':"You don't have this ERC 721 id"}
                user_address = request.user
                erc721 = ERC721.objects.filter(user_address=user_address)
                context['erc721s'] = erc721
                create1155form = Create1155Form(initial={'user_address': user_address})
                context['form'] = create1155form
                return render(request,'app/create1155.html', context)
            # call contract、 create_update DB
            if form.is_valid():
                # print(form)
                ERC721_id = form.cleaned_data['erc721_id']
                # ERC721_id = int(ERC721_id)
                print(ERC721_id)
                amount = form.cleaned_data['amount']
                amount = int(amount)
                print(amount)
                erc1155_name = form.cleaned_data['erc1155_name']
                seller_address = request.user
                seller_address = str(seller_address)
                # contract_address = web3.toChecksumAddress("0x74DC05a255E7Af98a2f83F1BC059862e973fda3C") # 确保我们的地址是校验格式
                # contract = web3.eth.contract(abi=erc1155_abi,address=contract_address) # 建立 contract 物件
                # print(f'transaction -> {seller_address}, {amount}, {ERC721_id}')
                # transaction = contract.functions.RealArtCopy(seller_address,amount,ERC721_id).buildTransaction(
                    # {
                        # 'from': platform_address['public_address'],
                        # 'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                        # 'gasPrice': web3.eth.gas_price,
                    # }
                # )
                # print('after transaction')
                # print('sign_transaction')
                # signed_tx = web3.eth.account.sign_transaction(transaction, platform_address['private_address'])
                # print(f'signed_tx: {signed_tx} \n signed_tx.rawTransaction: {signed_tx.rawTransaction}')
                # txn_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
                # print('send_raw_transaction')
                # txn_receipt = web3.eth.wait_for_transaction_receipt(txn_hash)
                # print('wait_for_transaction_receipt')
                # transhash = txn_receipt['transactionHash'].hex()
                # print('txn_receipt')
                receipt_url = "https://goerli.etherscan.io/tx/0x57ebfa640e9db3eb1f1a5ab17d800ad5acde4bf55bb17bb42aec0aef829b2fad"
                # Transaction’s details
                # print("看收據",txn_receipt)
                # print(f'receipt_url:{receipt_url}')
                form.save()
                #  update 1155id 跟 etherscan url
                from .models import ERC1155, ERC721
                erc721 = ERC721.objects.filter(erc721_id=ERC721_id).first()
                ERC1155.objects.filter(user_address=user_address,erc721_id=erc721.erc721_id).update(etherscan_url=receipt_url,img = erc721.img)
                # context = { 'Receipt' : receipt_url}
                return render(request,'app/create_nft.html' )
            return render(request,'app/create_nft.html')


# NFT 1155 Operations -> Contract : 查詢 Owner、Transfer，DB Update Data
#  update DB 同步資料 ?
def call_ERC1155_balanceOF(account,id):
    account = Web3.toChecksumAddress(account)
    id = int(id)
    ERC1155_contract = web3.eth.contract(abi=erc1155_abi,address=contract_erc1155_address)
    ERC1155_balance = ERC1155_contract.functions.balanceOf(account, id).call()
    print("balance :" , ERC1155_balance)
    return ERC1155_balance

#  update DB 轉換 user address、call contract 交易
def ERC1155_safe_transfer(_from , _to , id , amount , data):
    from .models import ERC1155
    Art = web3.eth.contract(abi=erc1155_abi, address=contract_erc1155_address)
    construct_txn = Art.functions.safeTransferFrom(_from, _to ,id , amount , data).buildTransaction(
        {
            'from': platform_address['public_address'],
            'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
            'gasPrice': web3.eth.gas_price,
        }
    )
    tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address']) # 簽名
    tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction) # transaction送出並且等待回傳
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    transhash = tx_receipt['transactionHash'].hex()
    recepit_url = "https://goerli.etherscan.io/tx/"+transhash
    ERC1155.objects.filter(user_address=_from).update(user_address=_to)
    print(recepit_url)
    return recepit_url


# Create_NFT_Result
class Create_NFT_Result(View):
        def get(self, request, *args, **kwargs):
            # get Transaction result and show it
            return render(request,'app/create_nft_result.html')
        def post(self, request, *args, **kwargs):
            return render(request,'app/create_nft_result.html' )



# Choose how to sell
class How_to_sell(View):
        def get(self, request, *args, **kwargs):
            return render(request,'app/how_to_sell.html' )
        def post(self, request, *args, **kwargs):
            return render(request,'app/how_to_sell.html' )


class Buy_NFT(View):
        def get(self, request, *args, **kwargs):
            return render(request,'app/buy_nft.html' )
        def post(self, request, *args, **kwargs):
            return render(request,'app/buy_nft.html' )

# 拍賣區 ===========
# Create Auction
from .forms import CreateAuctionForm
from app.contract.bytecode.auction_abi import auction_abi
from app.contract.bytecode.auction_bytecode import auction_byte
import datetime

@method_decorator(csrf_exempt, name='dispatch')
class Create_auction(View):
    def get(self, request, *args, **kwargs):
        from .models import User
        user_address = request.user
        user = User.objects.filter(public_address=user_address).first()
        form = CreateAuctionForm(initial={'seller_addr': user_address})
        return render(request,'app/create_auction.html',{'form':form,'message':'','user':user} )
    def post(self, request, *args, **kwargs):
        form = CreateAuctionForm(request.POST)
        user_address = request.user
        form_createauction = CreateAuctionForm(initial={'seller_addr': user_address})
        # 日期 判斷
        date_time = request.POST.get('datatime1')
        print(date_time)
        year = int(date_time[0:4])
        print(year)
        m=int(date_time[5:7])
        print(m)
        d=int(date_time[8:10])
        print(d)
        print(date_time)
        today = datetime.datetime.now()
        print(datetime.datetime.now())
        t_y = int(today.year)
        print(t_y)
        t_m = int(today.month)
        t_d = int(today.day)
        print((year < t_y))
        print((t_y==year and m<t_m ) )
        print((t_y==year and m==t_m and d < t_d))
        if (year < t_y) or (t_y==year and m<t_m ) or (t_y==year and m==t_m and d < t_d):
            return render(request,'app/create_auction.html',{'form':form_createauction,'message':"Datetime Invalid"} )
        # date_time = date_time[0:10] + date_time[13:17] +':00'
        date_time = f"{year}-{m}-{d} {date_time[-5:]}:00"
        print(f'date_time:{date_time}')
        print('data time valid')
        # 接到資料 -> 存到 DB -> call 合約 -> 存 etherscan url 到 DB-> 顯示 etherscan url
        if form.is_valid():
            #  check user has 721 or 1155 id | amount<持有量 , if not render the same page
            from .models import ERC721, ERC1155, Auction,Direct_Auction
            user_address = str(request.user)
            product_id = form.cleaned_data['product_id']
            category = form.cleaned_data['category']
            amount = form.cleaned_data['amount']
            if category == 0:
                erc721 = ERC721.objects.filter(user_address=user_address,erc721_id=product_id).first()
                auction = Auction.objects.filter(seller_addr=user_address,product_id=product_id,category=0).first()
                direct_auction = Direct_Auction.objects.filter(seller_addr=user_address,product_id=product_id,category=1).first()
                if erc721 == None:
                    return render(request,'app/create_auction.html',{'form':form_createauction,'message':"You don't have this ERC721"} )
                if amount > 1 or direct_auction != None :
                    return render(request,'app/create_auction.html',{'form':form_createauction,'message':"You don't have this amount of ERC721"} )
                if auction or direct_auction:
                    return render(request,'app/create_auction.html',{'form':form_createauction,'message':"This ERC721 is already on sale"} )
            elif category == 1:
                erc1155 = ERC1155.objects.filter(user_address=user_address,erc721_id=product_id).first()
                auction = Auction.objects.filter(seller_addr=user_address,product_id=product_id,category=1).first()
                direct_auction = Direct_Auction.objects.filter(seller_addr=user_address,product_id=product_id,category=1).first()
                if erc1155 == None:
                    return render(request,'app/create_auction.html',{'form':form_createauction,'message':"You don't have this ERC1155"} )
                if (erc1155.amount-auction.amount-direct_auction.amount) < amount:
                    return render(request,'app/create_auction.html',{'form':form_createauction,'message':"You don't have this amount of ERC1155"} )
            form.save()
            # 接收資料 [_beneficiary, _biddingTime, _highestBid]
            _beneficiary = str(request.user)
            # _beneficiary = Web3.toChecksumAddress(_beneficiary) #轉換成checksum address
            _biddingTime = form.cleaned_data['auction_time'] # 拍賣時間
            print(f'_biddingTime:{_biddingTime}')
            _biddingTime = int(_biddingTime) * 86400 # 乘一天的秒數
            _highestBid = form.cleaned_data['starting_price'] # 起拍價
            _highestBid = int(_highestBid)
            print(f'_highestBid:{_highestBid}')
            # call 合約
            # Core = web3.eth.contract(abi=auction_abi, bytecode=auction_byte)
            # MAX_GAS_ETHER = 0.0005
            # gas_price = float(web3.fromWei(web3.eth.gas_price, 'ether'))
            # allowed_gas = int(MAX_GAS_ETHER/gas_price)
            # print('construct_txn = Core.constructor(_biddingTime,_beneficiary,_highestBid).buildTransaction')
            # print(f'web3.eth.gas_price {web3.eth.gas_price}')
            # construct_txn = Core.constructor(_biddingTime,_beneficiary,_highestBid).buildTransaction(
            #         {
            #             'from': platform_address['public_address'],
            #             'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
            #             'gasPrice': web3.eth.gas_price,
            #             # 'chainId': 5,
            #         }
            #     )
            # print('construct_txn = Core.constructor(_biddingTime,_beneficiary,_highestBid).buildTransaction')
            # tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
            # print(f'tx_create{tx_create}')
            # tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
            # print(f'tx_hash{tx_hash}')
            # tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
            # print(f'tx_receipt{tx_receipt}')
            # contract_address = tx_receipt['contractAddress']
            # print(f'contract_address{contract_address}')
            # transhash = tx_receipt['transactionHash'].hex()
            # print(f'transhash{transhash}')
            # recepit_url = "https://goerli.etherscan.io/tx/"+transhash
            # print(f'recepit_url: {recepit_url}')
            # auction_owner = call_auction_beneficiary(contract_address)
            # auction_end_time = call_auction_auctionEndTime(contract_address)
            # print(f'contract info:\nauction_owner:{auction_owner}\nauction_end_time{auction_end_time}')
            # 存 etherscan url 到 DB 、 img
            from .models import Auction
            erc721 = ERC721.objects.filter(erc721_id=product_id).first()
            Auction.objects.filter(seller_addr=_beneficiary,product_id=product_id).update(starting_time=date_time, img = erc721.img, latest_price = _highestBid )
            # Auction.objects.filter(seller_addr=_beneficiary).update(etherscan_url=recepit_url,contract_address=contract_address)
            # 發布後更改 auction 狀態
            latest_obj= Auction.objects.last()
            latest_obj.status = 0
            latest_obj.save()
            print(f'latest_obj : {latest_obj.status}')
            # latest_obj= Auction.objects.filter(seller_addr=_beneficiary).order_by('-id').first().update(status=0)
            return render(request,'app/create_auction_result.html',{'message':''})
        return render(request,'app/create_auction_result.html',{'message':''})

@csrf_exempt
def getDatetim11(requet):
    # 接現在時間、去撈一天內的時間
    # 給前端 starting_time 、 id 、status_deploy
    # 前端回傳 id
    # deploy
    return JsonResponse({'result':True}) 


# 2 function 1  form datetim 、 deploy
@csrf_exempt
def getDatetime(request):
    if request.method == 'POST':
        from .models import Auction
        datetime_now = request.POST.get('now')
        print(f'datetime_now{datetime_now}')
        currentDateAndTime = datetime.now()
        print(f'currentDateAndTime:{currentDateAndTime}')
        dt_s= datetime.now()  # 2018-7-15
        print(dt_s)
        dt_e = (dt_s- datetime.timedelta(1))  # 2018-7-08
        print(dt_e)
        auctions = Auction.objects.filter(end_time__range=[dt_s, dt_e])
        print(auctions)
        for auction in auctions:
            if auction.status_deploy:
                deployAuction(auction)
        return JsonResponse({'result':True})
    if request.method == 'GET':
        from .models import Auction
        from django.utils.dateparse import parse_date
        datetime_now = request.GET.get('now')
        datetime_now = str(datetime_now)
        print(type(datetime_now))
        # datetime_now = parse_date(datetime_now)
        datetime_start = request.GET.get('start')
        print(type(datetime_start))
        datetime_start = str(datetime_start)
        # datetime_start = parse_date(datetime_start)
        # print(f'datetime_now{datetime_now}')
        currentDateAndTime = datetime.datetime.now()
        print(f'currentDateAndTime:{currentDateAndTime}')
        dt_s= datetime.datetime.now()  # 2018-7-15
        print(f'dt_s{dt_s}')
        # dt_s = str(dt_s)
        print(dt_s)
        dt_e = (dt_s- datetime.timedelta(1))  # 2018-7-08
        dt_s = str(dt_s)
        dt_s = dt_s[0:19]
        print(f'dt_s{dt_s}')
        dt_e = str(dt_e)
        dt_e = dt_e[0:19]
        print(f'dt_e{dt_e}')
        # auctions = Auction.objects.filter(end_time__range=[dt_s, dt_e])
        # auctions = Auction.objects.filter(starting_time=[datetime_start, datetime_now])
        auctions = Auction.objects.filter(starting_time=[dt_s, dt_e])
        print(auctions)
        for auction in auctions:
            if auction.status_deploy:
                deployAuction(auction)
        return JsonResponse({'result':True})


def deployAuction_2(auction):
    print('有拍賣需要 deploy')
    # call 合約
    _biddingTime = int(auction.auction_time)
    _beneficiary = w3.toChecksumAddress(auction.seller_addr)
    _highestBid = int(auction.starting_price)
    Core = web3.eth.contract(abi=auction_abi, bytecode=auction_byte)
    MAX_GAS_ETHER = 0.0005
    gas_price = float(web3.fromWei(web3.eth.gas_price, 'ether'))
    allowed_gas = int(MAX_GAS_ETHER/gas_price)
    construct_txn = Core.constructor(_biddingTime,_beneficiary,_highestBid).buildTransaction(
                                {
                                    'from': platform_address['public_address'],
                                    'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                                    'gasPrice': web3.eth.gas_price,
                                    'chainId': 5,
                                }
                            )
    tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
    tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    contract_address = tx_receipt['contractAddress']
    transhash = tx_receipt['transactionHash'].hex()
    recepit_url = "https://goerli.etherscan.io/tx/"+transhash
    print(f'recepit_url: {recepit_url}')
    auction_owner = call_auction_beneficiary(contract_address)
    auction_end_time = call_auction_auctionEndTime(contract_address)
    print(f'contract info:\nauction_owner:{auction_owner}\nauction_end_time{auction_end_time}')
                        # 存 etherscan url 到 DB 、 img
    from .models import Auction
    erc721 = ERC721.objects.filter(erc721_id=auction.product_id).first()
    Auction.objects.filter(seller_addr=_beneficiary).update(etherscan_url=recepit_url,contract_address=contract_address)
    # 發布後更改 auction 狀態
    latest_obj= Auction.objects.last()
    latest_obj.status = 0
    latest_obj.save()
    print(f'latest_obj : {latest_obj.status}')

# Auction Contract Operation 出價格、結束拍賣、撤回出價、查看最高出價者、查看最高出價、#查看發起拍賣的人、查看拍賣結束時間

# 撤回出價 ?

# auction bid 是否是 auction record in DB 要存的資料，還是只要儲存最終結果即可?
# 出價 [bidder=競標者,amount=出價價格,contract_auction_address]
def auction_bid(bidder , amount, contract_auction_address):
    amount = int(amount)
    bidder = web3.toChecksumAddress(bidder) 
    BID = web3.eth.contract(abi=auction_abi, address=contract_auction_address)
    construct_txn = BID.functions.bid(bidder, amount).buildTransaction(
                    {
                    'from': platform_address['public_address'],
                    'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                    'gasPrice': web3.eth.gas_price,
                }
            )
    tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
    tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    transhash = tx_receipt['transactionHash'].hex()
    print('txn_receipt')
    recepit_url = "https://goerli.etherscan.io/tx/"+transhash
    print(recepit_url)
    return recepit_url

#結束拍賣
def auction_auctionEnd(contract_auction_address): 
    Withdraw = web3.eth.contract(abi=auction_abi, address=contract_auction_address)
    construct_txn = Withdraw.functions.auctionEnd().buildTransaction(
                    {
                         'from': platform_address['public_address'],
                         'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                       'gasPrice': web3.eth.gas_price,
                   }
                 )
    tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
    tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    transhash = tx_receipt['transactionHash'].hex()
    print('txn_receipt')
    recepit_url = "https://goerli.etherscan.io/tx/"+transhash
    print(recepit_url)
    return recepit_url


#查看最高出價者
def call_auction_highestBidder(contract_auction_address): 
    auction_contract = web3.eth.contract(abi=auction_abi, address=contract_auction_address)
    auction_highestBidder = auction_contract.functions.highestBidder().call()
    print("highestBidder :" , auction_highestBidder) # highestBidder : 0x0000000000000000000000000000000000000000 ，因為該contract沒有人用bid function
    return auction_highestBidder 


#最高出價
def call_auction_highestBid(contract_auction_address):  
    auction_contract = web3.eth.contract(abi=auction_abi, address=contract_auction_address)
    auction_highestBid = auction_contract.functions.highestBid().call()
    print("highestBid :" , auction_highestBid)  #highestBid : 1，因為沒有人出價，所以為起拍價
    return auction_highestBid


#查看發起拍賣的人
def call_auction_beneficiary(contract_auction_address):  
    auction_contract = web3.eth.contract(abi=auction_abi, address=contract_auction_address)
    auction_beneficiary = auction_contract.functions.beneficiary().call()
    print("beneficiary :" , auction_beneficiary)
    return auction_beneficiary


#查看拍賣結束時間
def call_auction_auctionEndTime(contract_auction_address):  
    auction_contract = web3.eth.contract(abi=auction_abi, address=contract_auction_address)
    auction_auctionEndTime = auction_contract.functions.auctionEndTime().call()
    struct_time = time.localtime(auction_auctionEndTime)
    timeString = time.strftime("%Y-%m-%d %H:%M:%S", struct_time)
    
    print("aunctionEndTime :" , timeString) #aunctionEndTime : 2022-09-12 12:40:14
    return timeString


class Create_auction_result(View):
    def get(self, request, *args, **kwargs):
        return render(request,'app/create_auction_result.html' )
    def post(self, request, *args, **kwargs):
        return render(request,'app/create_auction_result.html' )

# # 排成每分鐘檢查一次 DB 有沒有需要發佈的拍賣合約、發布完要改狀態
# import time
# import datetime
# import threading
# def schedule1():
#     while True:
#         # 檢查 Auction 是否有需要 deploy 的
#         from .models import Auction
#         # 取現在
#         today = datetime.datetime.now()
#         print(f'{today} check for auction')
#         print(type(today))
#         t_y = int(today.year)
#         print(t_y)
#         t_m = int(today.month)
#         print(t_m)
#         t_d = int(today.day)
#         print(t_d)
#         t_hour = int(today.hour)
#         print(t_hour)
#         t_minute = int(today.minute)
#         print(t_minute)
#         # 取 DB
#         auctions = Auction.objects.all()
#         if auctions != None:
#             for auction in auctions:
#                 print(auction.starting_time)
#                 print(type(auction.starting_time))
#                 auction_starting_time = auction.starting_time
#                 auction_starting_time = auction_starting_time.strftime("%Y/%m/%d %H:%M:%S")
#                 year = int(auction_starting_time[0:4])
#                 month = int(auction_starting_time[5:7])
#                 day = int(auction_starting_time[8:10])
#                 hour = int(auction_starting_time[11:13])
#                 minute = int(auction_starting_time[14:16])
#                 print(f'year{year},month{month},day{day},hour{hour},{minute}')
#                 print(f'(t_y>year){(t_y>year)},(t_y==year and t_m>month){(t_y==year and t_m>month)},(t_y==year and t_m==month and t_d>day){(t_y==year and t_m==month and t_d>day)},(t_y==year and t_m==month and t_d==day and t_hour>hour{(t_y==year and t_m==month and t_d==day and t_hour>hour)},(t_y==year and t_m==month and t_d==day and t_hour>hour or t_minute>minute){(t_y==year and t_m==month and t_d==day and t_hour>hour or t_minute>minute)}')
#                 if (t_y>year) or (t_y==year and t_m>month) or (t_y==year and t_m==month and t_d>day) or (t_y==year and t_m==month and t_d==day and t_hour>hour) or (t_y==year and t_m==month and t_d==day and t_hour>hour or t_minute>minute):
#                     print('有拍賣需要 deploy')
#                     # call 合約
#                     _biddingTime = int(auction.auction_time)
#                     _beneficiary = w3.toChecksumAddress(auction.seller_addr)
#                     _highestBid = int(auction.starting_price)
#                     Core = web3.eth.contract(abi=auction_abi, bytecode=auction_byte)
#                     MAX_GAS_ETHER = 0.0005
#                     gas_price = float(web3.fromWei(web3.eth.gas_price, 'ether'))
#                     allowed_gas = int(MAX_GAS_ETHER/gas_price)
#                     construct_txn = Core.constructor(_biddingTime,_beneficiary,_highestBid).buildTransaction(
#                                 {
#                                     'from': platform_address['public_address'],
#                                     'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
#                                     'gasPrice': web3.eth.gas_price,
#                                     'chainId': 5,
#                                 }
#                             )
#                     tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
#                     tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
#                     tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
#                     contract_address = tx_receipt['contractAddress']
#                     transhash = tx_receipt['transactionHash'].hex()
#                     recepit_url = "https://goerli.etherscan.io/tx/"+transhash
#                     print(f'recepit_url: {recepit_url}')
#                     auction_owner = call_auction_beneficiary(contract_address)
#                     auction_end_time = call_auction_auctionEndTime(contract_address)
#                     print(f'contract info:\nauction_owner:{auction_owner}\nauction_end_time{auction_end_time}')
#                         # 存 etherscan url 到 DB 、 img
#                     from .models import Auction
#                     erc721 = ERC721.objects.filter(erc721_id=auction.product_id).first()
#                     Auction.objects.filter(seller_addr=_beneficiary).update(etherscan_url=recepit_url,contract_address=contract_address)
#                         # 發布後更改 auction 狀態
#                     latest_obj= Auction.objects.filter(seller_addr=_beneficiary).latest('id')
#                     print(latest_obj)
#                     latest_obj.update(status=0)
#         time.sleep(60)

# thread = threading.Thread(target=schedule1)
# thread.start()
class Writer_all(View):
    def get(self, request, *args, **kwargs):
        # call DB
        from .models import User
        user_address = request.user
        user = User.objects.filter(public_address=user_address).first()
        context = {'user':user}
        return render(request,'app/writer_all.html', context )
    def post(self, request, *args, **kwargs):
        return render(request,'app/writer_all.html', context)

class Writer_subscribe(View):
    def get(self, request, *args, **kwargs):
        # call DB
        from .models import User
        user_address = request.user
        user = User.objects.filter(public_address=user_address).first()
        context = {'user':user}
        return render(request,'app/writer_subscribe.html', context )
    def post(self, request, *args, **kwargs):
        return render(request,'app/writer_subscribe.html', context)

# ? 時間跳 status 要狀態
# List Auction
class List_auction(View):
    def get(self, request, *args, **kwargs):
        # call DB
        from .models import Auction, User
        user_address = request.user
        user = User.objects.filter(public_address=user_address).first()
        auctions_now = Auction.objects.filter(status=0).order_by('created_at')
        auctions_pre = None
        auctions_end = None
        context = {'auctions_pre':auctions_pre,'auctions_now':auctions_now,'auctions_end':auctions_end, 'user':user}
        return render(request,'app/list_auction.html', context )
    def post(self, request, *args, **kwargs):
        from .models import Auction
        data = request.POST.get('PRE')
        auctions_pre= request.POST.get('PRE')
        auctions_now= request.POST.get('NOW')
        auctions_end= request.POST.get('END')
        if auctions_pre == 'Pre':
            auctions_pre = Auction.objects.filter(status=2).order_by('created_at')
        if auctions_now == 'Now':
            auctions_now = Auction.objects.filter(status=0).order_by('created_at')
        if auctions_end == 'End':
            auctions_end = Auction.objects.filter(status=1).order_by('-created_at')
        context = {'auctions_pre':auctions_pre,'auctions_now':auctions_now,'auctions_end':auctions_end}

        return render(request,'app/list_auction.html', context)

class Detail_auction(View):
    def get(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        from .models import Auction
        from .models import User as user_2
        user_addr = request.user
        user_addr = str(user_addr)
        user = user_2.objects.filter(public_address=user_addr).first()
        auction = Auction.objects.filter(pk=pk).first()
        context = {'auction':auction, 'user':user}
        return render(request,'app/detail_auction.html',context)
    def post(self, request, *args, **kwargs):
        return render(request,'app/detail_auction.html')

class Detail_NFT721(View):
    def get(self, request, *args, **kwargs):
        pk = self.kwargs['pk'] 
        from .models import ERC721
        from .models import User as user_2
        user_addr = request.user
        user_addr = str(user_addr)
        user = user_2.objects.filter(public_address=user_addr).first()
        nft721 = ERC721.objects.filter(pk=pk).first()
        context = {'nft721':nft721, 'user':user}
        return render(request,'app/detail_721.html',context)
    def post(self, request, *args, **kwargs):
        return render(request,'app/detail_721.html')

@csrf_exempt
def confirm_auction(request):
    if request.method == 'POST':
        from .models import Auction, Auction_Record
        user = request.user
        user = str(user)
        print('=========================')
        auction_id = request.POST.get('auction_id')
        print(auction_id)
        bid_price = request.POST.get('bid_price')
        print(bid_price)
        # 改變 DB 最高競標價格
        Auction.objects.filter(id=auction_id).update(latest_price=bid_price)
        Auction_Record.objects.create(seller_addr=user,auction_id=auction_id,bid_price=bid_price)
        auction = Auction.objects.filter(id=auction_id).first()
        # 改變區塊鏈上 最高競標價格
        # print(f'bid info: {user}, {bid_price}, {auction.contract_address}')
        # auction_url = auction_bid(user , bid_price, auction.contract_address)
        # print(f'auction_url bid 的 url:{auction_url}')
        # auction_highestBidder = call_auction_highestBidder(auction.contract_address) #查看最高出價者
        # auction_highestBid = call_auction_highestBid(auction.contract_address) #最高出價
        # print(f'區塊鏈上 auction_highestBidder:{auction_highestBidder},auction_highestBid:{auction_highestBid}')
        return JsonResponse({'result':True})

# 當競拍價格等於一口價
# status 改變 、auction record、auction 到 end
# @csrf_exempt
# def lastest_it_now(request):
#     # auction status
#     auction_id = request.POST.get('auction_id')
#     bid_price = request.POST.get('bid_price')
#     from .models import Auction, Auction_Record
#     user = request.user
#     user = str(user)
#     Auction.objects.filter(id=auction_id).update(status=1)
#     Auction_Record.objects.create(seller_addr=user,auction_id=auction_id,bid_price=bid_price)
#     auction = Auction.objects.filter(id=auction_id).first()
#     auction_auctionEnd(auction.contract_address)

#     # NFT 先判定是 1155 or 721 在轉換
#     if auction.category == 0: # 721 (call 此 function DB 也會更新)
#         erc721_obj = ERC721.objects.filter(erc721_id=auction.product_id).first()
#         ERC721_safe_transfer(auction.seller_addr , user , auction.product_id , erc721_obj.contract_address)
#     elif auction.category == 1: #1155 (call 此 function DB 也會更新)
#         ERC1155_safe_transfer(auction.seller_addr ,user, auction.product_id , auction.amount , '0x6162636400000000000000000000000000000000000000000000000000000000')
    
#     # Platform Token 轉換 ，先轉到平台再從平台轉到使用者
#     # transferToPlatform(_from, _value, _fee)
#     transferToPlatform(user, bid_price, 0.1)
#     # transferFromPlatform(_to, _value)
#     transferFromPlatform(auction.seller_addr, bid_price)
#     return JsonResponse({'result':True})




# NFT seller -> buyer 
# 平台幣 buyer ->  seller
# auction status
@csrf_exempt
def confirm_buy_it_now(request):
    if request.method == 'POST':
        # auction status
        auction_id = request.POST.get('auction_id')
        bid_price = request.POST.get('bid_price')
        int_price = int(bid_price)
        from .models import Auction, Auction_Record,ERC721,User
        user = request.user
        user = str(user)
        user_token = User.objects.filter(public_address=user).first()
        User.objects.filter(public_address=user).update(platform_token = user_token.platform_token-int_price)
        Auction.objects.filter(id=auction_id).update(status=1,latest_price=bid_price)
        Auction_Record.objects.create(seller_addr=user,auction_id=auction_id,bid_price=bid_price)
        auction = Auction.objects.filter(id=auction_id).first()
        # auction_end_url = auction_auctionEnd(auction.contract_address)
        # print(f'auction_end_url: {auction_end_url}')
        # NFT 先判定是 1155 or 721 在轉換
        if auction.category == 0: # 721 (call 此 function DB 也會更新)
            erc721_obj = ERC721.objects.filter(erc721_id=auction.product_id).first()
            ERC721.objects.filter(erc721_id=auction.product_id).update(user_address = user)
            # print(f'轉換NFT前的持有者 : {erc721_obj.user_address}')
            # ERC721_safe_transfer(auction.seller_addr , user , auction.product_id , erc721_obj.contract_address)
            # erc721_owner = call_ERC721_walletOfOwner(user , erc721_obj.contract_address)
            # print(f'轉換平台幣後的持有者 : {erc721_owner}')
            # print(f'轉換NFT後的持有者 : {erc721_obj.user_address}')
        elif auction.category == 1: #1155 (call 此 function DB 也會更新)
            ERC1155_safe_transfer(auction.seller_addr ,user, auction.product_id , auction.amount , '0x6162636400000000000000000000000000000000000000000000000000000000')
            erc1155_balance = call_ERC1155_balanceOF(user,id)
            print(f'轉換後買家{user} 持有 {id} 數量 {erc1155_balance} ')
        # Platform Token 轉換 ，先轉到平台再從平台轉到使用者
        # transferToPlatform(_from, _value, _fee)
        # seller_865 = call_ERC865(auction.seller_addr)
        # buyer_865 = call_ERC865(user)
        # print(f'交易完成前 賣家 865 {seller_865}, 買家 865{buyer_865}')
        # transferToPlatform(user, bid_price, 1)
        # transferFromPlatform(_to, _value)
        # transferFromPlatform(auction.seller_addr, bid_price)
        # seller_865 = call_ERC865(auction.seller_addr)
        # buyer_865 = call_ERC865(user)
        # print(f'交易完成後 賣家 865 {seller_865}, 買家 865{buyer_865}')
        return JsonResponse({'result':True})
    if request.method == 'GET':
        # auction status
        auction_id = request.POST.get('auction_id')
        bid_price = request.POST.get('bid_price')
        int_price = int(bid_price)
        from .models import Auction, Auction_Record,ERC721,User
        user = request.user
        user = str(user)
        user_token = User.objects.filter(public_address=user).first()
        User.objects.filter(public_address=user).update(platform_token = user_token.platform_token-int_price)
        Auction.objects.filter(id=auction_id).update(status=1,latest_price=bid_price)
        Auction_Record.objects.create(seller_addr=user,auction_id=auction_id,bid_price=bid_price)
        auction = Auction.objects.filter(id=auction_id).first()
        # auction_end_url = auction_auctionEnd(auction.contract_address)
        # print(f'auction_end_url: {auction_end_url}')
        # NFT 先判定是 1155 or 721 在轉換
        if auction.category == 0: # 721 (call 此 function DB 也會更新)
            erc721_obj = ERC721.objects.filter(erc721_id=auction.product_id).first()
            ERC721.objects.filter(erc721_id=auction.product_id).update(user_address = user)
            # print(f'轉換NFT前的持有者 : {erc721_obj.user_address}')
            # ERC721_safe_transfer(auction.seller_addr , user , auction.product_id , erc721_obj.contract_address)
            # erc721_owner = call_ERC721_walletOfOwner(user , erc721_obj.contract_address)
            # print(f'轉換平台幣後的持有者 : {erc721_owner}')
            # print(f'轉換NFT後的持有者 : {erc721_obj.user_address}')
        elif auction.category == 1: #1155 (call 此 function DB 也會更新)
            ERC1155_safe_transfer(auction.seller_addr ,user, auction.product_id , auction.amount , '0x6162636400000000000000000000000000000000000000000000000000000000')
            erc1155_balance = call_ERC1155_balanceOF(user,id)
            print(f'轉換後買家{user} 持有 {id} 數量 {erc1155_balance} ')
        # Platform Token 轉換 ，先轉到平台再從平台轉到使用者
        # transferToPlatform(_from, _value, _fee)
        # seller_865 = call_ERC865(auction.seller_addr)
        # buyer_865 = call_ERC865(user)
        # print(f'交易完成前 賣家 865 {seller_865}, 買家 865{buyer_865}')
        # transferToPlatform(user, bid_price, 1)
        # transferFromPlatform(_to, _value)
        # transferFromPlatform(auction.seller_addr, bid_price)
        # seller_865 = call_ERC865(auction.seller_addr)
        # buyer_865 = call_ERC865(user)
        # print(f'交易完成後 賣家 865 {seller_865}, 買家 865{buyer_865}')
        return JsonResponse({'result':True})

# NFT seller -> buyer 
# 平台幣 buyer ->  seller
# auction status
@csrf_exempt
def confirm_buy_it_now_direct(request):
    if request.method == 'POST':
        from .models import Direct_Auction, Auction_Record,ERC721,ERC1155, User
        auction_id = request.POST.get('auction_id')
        buy_price = request.POST.get('buy_price')
        int_price = int(buy_price)
        # Auction Status change
        user = request.user
        user = str(user)
        user_token = User.objects.filter(public_address=user).first()
        User.objects.filter(public_address=user).update(platform_token = user_token.platform_token-int_price)
        Direct_Auction.objects.filter(id=auction_id).update(status=1)
        auction = Direct_Auction.objects.filter(id=auction_id).first()
        Auction_Record.objects.create(seller_addr=user,auction_id=auction_id,bid_price=buy_price)
        # Change NFT owner
        # NFT 先判定是 1155 or 721 在轉換
        if auction.category == 0: # 721 (call 此 function DB 也會更新)
            erc721_obj = ERC721.objects.filter(erc721_id=auction.product_id).first()
            ERC721.objects.filter(erc721_id=auction.product_id).update(user_address = user)
            # from .models import Direct_Auction, ERC721
            # # 存 etherscan url 到 DB 、 img \ update status
            # erc721  = ERC721.objects.filter(erc721_id=product_id).first()
            # Direct_Auction.objects.filter(seller_addr=seller_addr,product_id=product_id).update(starting_time=date_time, img = erc721.img,auction_time=_biddingTime,status=0)
            # # erc721_owner = call_ERC721_token_ownerOF(5, erc721_obj.contract_address)
            # print(f'轉換NFT前的持有者 : {erc721_owner}')
            # print(f'轉換NFT前的持有者 : {erc721_obj.user_address}')
            # print(f'auction.seller_addr: {auction.seller_addr}, user:{user},auction.product_id{auction.product_id},erc721_obj.contract_address:{erc721_obj.contract_address}')
            # ERC721_safe_transfer(erc721_owner , user , auction.product_id , erc721_obj.contract_address)
            # erc721_owner = call_ERC721_token_ownerOF(5, erc721_obj.contract_address)
            # print(f'轉換NFT後的持有者 : {erc721_owner}')
            # print(f'轉換NFT後的持有者 : {erc721_obj.user_address}')
        elif auction.category == 1: #1155 (call 此 function DB 也會更新)
            ERC1155_safe_transfer(auction.seller_addr ,user, auction.product_id , auction.amount , '0x6162636400000000000000000000000000000000000000000000000000000000')
            erc1155_balance = call_ERC1155_balanceOF(user,id)
            print(f'轉換後買家{user} 持有 {id} 數量 {erc1155_balance} ')
            # erc1155_obj = ERC1155.objects.filter(erc1155_id=auction.product_id).first()


        # Platform Token 轉換 ，先轉到平台再從平台轉到使用者
        # Transfer platform token
        # auction = Direct_Auction.objects.filter(id=auction_id).first()
        # seller_865 = call_ERC865(auction.seller_addr)
        # buyer_865 = call_ERC865(user)
        # print(f'交易完成前 賣家 865 {seller_865}, 買家 865{buyer_865}')
        # transferToPlatform(user, buy_price, 1)
        # transferFromPlatform(_to, _value)
        # transferFromPlatform(auction.seller_addr, buy_price)
        # seller_865 = call_ERC865(auction.seller_addr)
        # buyer_865 = call_ERC865(user)
        # print(f'交易完成後 賣家 865 {seller_865}, 買家 865{buyer_865}')
        return JsonResponse({'result':True})

        


import time
import pandas as pd
import math
import datetime as dt
@csrf_exempt
def auction_time(request):
    if request.method == 'POST':
        from .models import Auction
        auction_id = request.POST.get('auction_id')
        auction_id = int(auction_id)
        print(f'auction_id: {auction_id}')
        auction = Auction.objects.filter(id=auction_id).first()
        print(auction)
        delta = calculate_now_auctiontime(auction.contract_address)
        print(f'auction.contract_address: {auction.contract_address}')
        hour = math.floor(delta.seconds/3600)
        minute = math.floor((delta.seconds - hour*3600)/60)
        seconds = math.floor(delta.seconds - hour*3600 - minute * 60)
        print(f'delta{delta}, hour:{hour}, minute:{minute}, seconds:{seconds}')
        return JsonResponse({'day':delta.days,'hour':hour,'min':minute,"sec":seconds})

    if request.method == 'GET':
        from .models import Auction
        acution_id = request.GET.get('acution_id')
        auction = Auction.objects.filter(id=acution_id).first()
        delta = calculate_now_auctiontime(auction.contract_address)
        print(f'auction.contract_address: {auction.contract_address}')
        hour = math.floor(delta.seconds/3600)
        minute = math.floor((delta.seconds - hour*3600)/60)
        seconds = math.floor(delta.seconds - hour*3600 - minute * 60)
        print(f'delta{delta}, hour:{hour}, minute:{minute}, seconds:{seconds}')
        return JsonResponse({'day':delta.days,'hour':hour,'min':minute,"sec":seconds})


def calculate_now_auctiontime(contract_auction_address): #計算剩餘時間
    auction_contract = web3.eth.contract(abi=auction_abi, address=contract_auction_address)
    auction_auctionEndTime = auction_contract.functions.auctionEndTime().call()
    struct_time = time.localtime(auction_auctionEndTime)
    timeString = time.strftime("%Y-%m-%d %H:%M:%S", struct_time)
    timeString = pd.to_datetime(timeString, format='%Y-%m-%d %H:%M:%S')  # 把結束時間轉換成 timedleta type
    now_time = date_2.now().strftime('%Y-%m-%d %H:%M:%S')
    now_time = pd.to_datetime(now_time, format='%Y-%m-%d %H:%M:%S') # 把目前的時間轉換成 timedleta type
    delta = timeString - now_time
    # ==  計算小時、分鐘、秒 ==
    hour = math.floor(delta.seconds/3600)
    minute = math.floor((delta.seconds - hour*3600)/60)
    seconds = math.floor(delta.seconds - hour*3600 - minute * 60)
    print("today is :", now_time)
    print("auctionEndTime :" , timeString)
    if(delta > dt.timedelta(seconds>=1)): # 如果剩餘時間>=1時,便顯示時間
        print("距離拍賣結束時間還有 " ,delta.days,"天",hour,"小時",minute,"分鐘",seconds,"秒") #距離拍賣結束時間還有   -3 天 16 小時 14 分鐘 26 秒
    else:
        print("拍賣已經結束了！") #拍賣已經結束了！
    return delta


# 直接販賣 ===========
# CRUD 直接販賣
# 直接販售
# 相關 class
# 相關 function
# Create Direct_sale
from .forms import Create_direct_saleForm
class Create_direct_sale(View):
    def get(self, request, *args, **kwargs):
        user_address = request.user
        form = Create_direct_saleForm(initial={'seller_addr': user_address})
        context = {'form':form,'message':''}
        return render(request,'app/create_direct_sale.html', context)

    def post(self, request, *args, **kwargs):
        form = Create_direct_saleForm(request.POST)
        user_address = request.user
        user_address = str(user_address)
        form_create_direct_auction = Create_direct_saleForm(initial={'seller_addr': user_address})
        # 收到資料 -> 資料輸入DB , 鎖定藝術品 --> return html(indext and msg[success or fail])
        # 判定 使用者持有該 NFT 及 數量
        date_time = request.POST.get('datatime1')
        print(f'date_time{date_time}')
        year = int(date_time[0:4])
        print(year)
        m=int(date_time[5:7])
        print(m)
        d=int(date_time[8:10])
        print(d)
        print(date_time)
        today = datetime.datetime.now()
        print(datetime.datetime.now())
        t_y = int(today.year)
        print(t_y)
        t_m = int(today.month)
        t_d = int(today.day)
        print((year < t_y))
        print((t_y==year and m<t_m ) )
        print((t_y==year and m==t_m and d < t_d))
        if (year < t_y) or (t_y==year and m<t_m ) or (t_y==year and m==t_m and d < t_d):
            return render(request,'app/create_direct_sale.html',{'form':form_create_direct_auction,'message':"Datetime Invalid"} )
        date_time = f"{year}-{m}-{d} {date_time[-5:]}:00"
        print(f'date_time:{date_time}')
        print('data time valid')
        if form.is_valid():
            print('enter if')
            #  check user has 721 or 1155 id | amount<持有量 , if not render the same page
            from .models import ERC721, ERC1155, Direct_Auction,Auction
            user_address = str(request.user)
            product_id = form.cleaned_data['product_id']
            category = form.cleaned_data['category']
            amount = form.cleaned_data['amount']
            # 拍賣時間、起拍價
            _biddingTime = form.cleaned_data['auction_time'] # 拍賣時間
            _biddingTime = int(_biddingTime) * 86400 # 乘一天的秒數
            _highestBid = form.cleaned_data['price'] # 一口價價格
            _highestBid = int(_highestBid)
            seller_addr = form.cleaned_data['seller_addr']
            product_id = form.cleaned_data['product_id']
            if category == 0:
                print('enter if0')
                erc721 = ERC721.objects.filter(user_address=user_address,erc721_id=product_id).first()
                auction = Direct_Auction.objects.filter(seller_addr=user_address,product_id=product_id,category=0).first()
                auction2 = Auction.objects.filter(seller_addr=user_address,product_id=product_id,category=0).first()
                if erc721 == None:
                    print('enter None')
                    return render(request,'app/create_direct_sale.html',{'form':form_create_direct_auction,'message':"You don't have this ERC721"} )
                if amount > 1 :
                    print('enter amout1')
                    return render(request,'app/create_direct_sale.html',{'form':form_create_direct_auction,'message':"You don't have this amount of ERC721"} )
                if auction or auction2:
                    print('enter auction')
                    return render(request,'app/create_direct_sale.html',{'form':form_create_direct_auction,'message':"This ERC721 is already on sale"} )
                form.save()
                # from .models import Direct_Auction, ERC721, ERC1155
                erc721  = ERC721.objects.filter(erc721_id=product_id).first()
                Direct_Auction.objects.filter(seller_addr=seller_addr,product_id=product_id).update(starting_time=date_time, img = erc721.img,auction_time=_biddingTime,status=0)
                return render(request,'app/create_auction_result.html',{'message':''})
  
            elif category == 1:
                print('enter if1')
                erc1155 = ERC1155.objects.filter(user_address=user_address,erc1155_id=product_id).first()
                auction = Direct_Auction.objects.filter(seller_addr=user_address,product_id=product_id,category=1).first()
                if erc1155 == None:
                    return render(request,'app/create_direct_sale.html',{'form':form_create_direct_auction,'message':"You don't have this ERC1155"} )
                if (erc1155.amount-auction.amount-auction2.amount) < amount:
                    return render(request,'app/create_direct_sale.html',{'form':form_create_direct_auction,'message':"You don't have this amount of ERC1155"} )
                form.save()
                # from .models import Direct_Auction, ERC721, ERC1155
                erc1155  = ERC1155.objects.filter(erc1155_id=product_id).first()
                Direct_Auction.objects.filter(seller_addr=seller_addr,product_id=product_id).update(starting_time=date_time, img = erc1155.img,auction_time=_biddingTime,status=0)
                return render(request,'app/create_auction_result.html',{'message':''})
            # 拍賣時間、起拍價
            # _biddingTime = form.cleaned_data['auction_time'] # 拍賣時間
            # _biddingTime = int(_biddingTime) * 86400 # 乘一天的秒數
            # _highestBid = form.cleaned_data['price'] # 一口價價格
            # _highestBid = int(_highestBid)
            # call 合約
            # Core = web3.eth.contract(abi=auction_abi, bytecode=auction_byte)
            # MAX_GAS_ETHER = 0.0005
            # gas_price = float(web3.fromWei(web3.eth.gas_price, 'ether'))
            # allowed_gas = int(MAX_GAS_ETHER/gas_price)
            # user_address_1 = Web3.toChecksumAddress(user_address)
            # construct_txn = Core.constructor(_biddingTime,user_address_1,_highestBid).buildTransaction(
            #         {
            #             'from': platform_address['public_address'],
            #             'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
            #             'gasPrice': web3.eth.gas_price,
            #             'chainId': 5,
            #         }
            #     )
            # tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
            # tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
            # tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
            # contract_address = tx_receipt['contractAddress']
            # transhash = tx_receipt['transactionHash'].hex()
            # recepit_url = "https://goerli.etherscan.io/tx/"+transhash
            # print(f'recepit_url: {recepit_url}')
            # auction_owner = call_auction_beneficiary(contract_address)
            # auction_end_time = call_auction_auctionEndTime(contract_address)
            # print(f'contract info:\nauction_owner:{auction_owner}\nauction_end_time{auction_end_time}')
            # save into DB
            # form.save()
            # seller_addr = form.cleaned_data['seller_addr']
            # product_id = form.cleaned_data['product_id']
            # from .models import Direct_Auction, ERC721, ERC1155
            # 存 etherscan url 到 DB 、 img \ update status
            # erc721  = ERC721.objects.filter(erc721_id=product_id).first()
            # erc1155  = ERC1155.objects.filter(erc1155_id=product_id).first()
            # Direct_Auction.objects.filter(seller_addr=seller_addr,product_id=product_id).update(starting_time=date_time, img = erc721.img,auction_time=_biddingTime,status=0)
            # Direct_Auction.objects.filter(seller_addr=seller_addr,product_id=product_id).update(starting_time=date_time, img = erc1155.img,auction_time=_biddingTime,status=0)
            # Direct_Auction.objects.filter(seller_addr=seller_addr,product_id=product_id).update(starting_time=date_time,)
            # return render(request,'app/create_auction_result.html',{'message':''})
        return render(request,'app/create_direct_sale.html',{'message':'Create Invalid form'})

# 排成每分鐘檢查一次 DB 有沒有需要轉變狀態的 direct auction、發布完要改狀態
import time
import datetime
import threading
# def schedule2():
#     while True:
#         # 檢查 Auction 是否有需要 deploy 的
#         from .models import Direct_Auction
#         # 取現在
#         today = datetime.datetime.now()
#         print(f'{today} check for auction')
#         print(type(today))
#         t_y = int(today.year)
#         print(t_y)
#         t_m = int(today.month)
#         print(t_m)
#         t_d = int(today.day)
#         print(t_d)
#         t_hour = int(today.hour)
#         print(t_hour)
#         t_minute = int(today.minute)
#         print(t_minute)
#         # 取 DB
#         auctions = Direct_Auction.objects.all()
#         if auctions != None:
#             for auction in auctions:
#                 print(auction.starting_time)
#                 print(type(auction.starting_time))
#                 auction_starting_time = auction.starting_time
#                 auction_starting_time = auction_starting_time.strftime("%Y/%m/%d %H:%M:%S")
#                 year = int(auction_starting_time[0:4])
#                 month = int(auction_starting_time[5:7])
#                 day = int(auction_starting_time[8:10])
#                 hour = int(auction_starting_time[11:13])
#                 minute = int(auction_starting_time[14:16])
#                 print(f'year{year},month{month},day{day},hour{hour},{minute}')
#                 print(f'(t_y>year){(t_y>year)},(t_y==year and t_m>month){(t_y==year and t_m>month)},(t_y==year and t_m==month and t_d>day){(t_y==year and t_m==month and t_d>day)},(t_y==year and t_m==month and t_d==day and t_hour>hour{(t_y==year and t_m==month and t_d==day and t_hour>hour)},(t_y==year and t_m==month and t_d==day and t_hour>hour or t_minute>minute){(t_y==year and t_m==month and t_d==day and t_hour>hour or t_minute>minute)}')
#                 if (t_y>year) or (t_y==year and t_m>month) or (t_y==year and t_m==month and t_d>day) or (t_y==year and t_m==month and t_d==day and t_hour>hour) or (t_y==year and t_m==month and t_d==day and t_hour>hour or t_minute>minute):
#                     print('有拍賣需要 deploy')
#                     # call 合約
#                     _biddingTime = int(auction.auction_time)
#                     _beneficiary = web3.toChecksumAddress(auction.seller_addr)
#                     _highestBid = int(auction.price)
#                     Core = web3.eth.contract(abi=auction_abi, bytecode=auction_byte)
#                     MAX_GAS_ETHER = 0.0005
#                     gas_price = float(web3.fromWei(web3.eth.gas_price, 'ether'))
#                     allowed_gas = int(MAX_GAS_ETHER/gas_price)
#                     construct_txn = Core.constructor(_biddingTime,_beneficiary,_highestBid).buildTransaction(
#                                 {
#                                     'from': platform_address['public_address'],
#                                     'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
#                                     'gasPrice': web3.eth.gas_price,
#                                     'chainId': 5,
#                                 }
#                             )
#                     tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
#                     tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
#                     tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
#                     contract_address = tx_receipt['contractAddress']
#                     transhash = tx_receipt['transactionHash'].hex()
#                     recepit_url = "https://goerli.etherscan.io/tx/"+transhash
#                     print(f'recepit_url: {recepit_url}')
#                     auction_owner = call_auction_beneficiary(contract_address)
#                     auction_end_time = call_auction_auctionEndTime(contract_address)
#                     print(f'contract info:\nauction_owner:{auction_owner}\nauction_end_time{auction_end_time}')
#                     # 存 etherscan url 到 DB 、 img
#                     from .models import Direct_Auction
#                     erc721 = ERC721.objects.filter(erc721_id=auction.product_id).first()
#                     Direct_Auction.objects.filter(seller_addr=_beneficiary).update(etherscan_url=recepit_url,contract_address=contract_address)
#                     Direct_Auction.objects.filter(seller_addr=_beneficiary,product_id=auction.product_id).update(img = erc721.img,auction_time=_biddingTime,status=0,etherscan_url=recepit_url,contract_address=contract_address)
#                     # 發布後更改 auction 狀態
#                     latest_obj= Direct_Auction.objects.filter(seller_addr=_beneficiary).latest('id')
#                     print(latest_obj)
#                     latest_obj.update(status=0)
#         time.sleep(60)

# thread = threading.Thread(target=schedule2)
# thread.start()

# ListView Direct_sale 
class List_direct_sale(View):
    def get(self, request, *args, **kwargs):
        # call DB 拿資料
        from .models import Direct_Auction, User
        user_address = request.user
        auctions_pre = Direct_Auction.objects.filter(status=2).order_by('created_at')
        auctions_now = Direct_Auction.objects.filter(status=0).order_by('created_at')
        auctions_end = Direct_Auction.objects.filter(status=1).order_by('-created_at')
        user = User.objects.filter(public_address=user_address).first()
        context = {'auctions_pre':auctions_pre,'auctions_now':auctions_now,'auctions_end':auctions_end, 'user':user}
        return render(request,'app/list_direct_sale.html', context)
    def post(self, request, *args, **kwargs):
        from .models import Direct_Auction
        # data = request.POST.get('PRE')
        # auctions_pre= request.POST.get('PRE')
        # auctions_now= request.POST.get('NOW')
        # auctions_end= request.POST.get('END')
        # if auctions_pre == 'Pre':
        #     auctions_pre = Direct_Auction.objects.filter(status=2).order_by('created_at')
        # if auctions_now == 'Now':
        #     auctions_now = Direct_Auction.objects.filter(status=0).order_by('created_at') 
        # if auctions_end == 'End':
        #     auctions_end = Direct_Auction.objects.filter(status=1).order_by('-created_at')
        auctions_pre = Direct_Auction.objects.filter(status=2).order_by('created_at')
        auctions_now = Direct_Auction.objects.filter(status=0).order_by('created_at')
        auctions_end = Direct_Auction.objects.filter(status=1).order_by('-created_at')
        context = {'auctions_pre':auctions_pre,'auctions_now':auctions_now,'auctions_end':auctions_end}
        return render(request,'app/list_direct_sale.html', context)


# DetailView Direct_sale 
class Detail_direct_sale(View):
    def get(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        from .models import Direct_Auction
        from .models import User as user_2
        user_addr = request.user
        user_addr = str(user_addr)
        user = user_2.objects.filter(public_address=user_addr).first()
        auction = Direct_Auction.objects.filter(pk=pk).first()
        context = {'auction':auction, 'user':user}
        return render(request,'app/detail_direct_sale.html',context)
    def post(self, request, *args, **kwargs):
        return render(request,'app/detail_direct_sale.html')

@csrf_exempt
def direct_confirm_buy_it_now(request):
    # Auction status
    auction_id = request.POST.get('auction_id')
    bid_price = request.POST.get('bid_price')
    from .models import Direct_Auction, Auction_Record,ERC721
    user = request.user
    user = str(user)
    Direct_Auction.objects.filter(id=auction_id).update(status=1)
    Auction_Record.objects.create(seller_addr=user,auction_id=auction_id,bid_price=bid_price)
    auction = Direct_Auction.objects.filter(id=auction_id).first()
    auction_end_url = auction_auctionEnd(auction.contract_address)
    print(f'auction_end_url : {auction_end_url}')
    # NFT 先判定是 1155 or 721 在轉換
    if auction.category == 0: # 721 (call 此 function DB 也會更新)
        erc721_obj = ERC721.objects.filter(erc721_id=auction.product_id).first()
        print(f'轉換NFT前的持有者 : {erc721_obj.user_address}')
        ERC721_safe_transfer(auction.seller_addr , user , auction.product_id , erc721_obj.contract_address)
        print(f'轉換NFT後的持有者 : {erc721_obj.user_address}')
    elif auction.category == 1: #1155 (call 此 function DB 也會更新)
        ERC1155_safe_transfer(auction.seller_addr ,user, auction.product_id , auction.amount , '0x6162636400000000000000000000000000000000000000000000000000000000')
    
    # Platform Token 轉換 ，先轉到平台再從平台轉到使用者
    # transferToPlatform(_from, _value, _fee)
    transferToPlatform(user, bid_price, 1)
    # transferFromPlatform(_to, _value)
    transferFromPlatform(auction.seller_addr, bid_price)
    return JsonResponse({'result':True})

# UpdateView Direct_sale [如果有人購買 erc1155交易藝術品 , erc865交易平台幣, DB] or [無人購買退還藝術品, DB]
#  settings
class Update_direct_sale(View):
    model = ''
    # can use field =['field_name'] or just __all__ (2 underscore)
    fields = ['title', 'description','complete']
    # when the form is submitted, we can redirectuser successfully to different page
    # tasks is url name in urls/py
    success_url = reverse_lazy('tasks')

#  setting
# Cancel sale Direct_sale
class Delete_direct_sale(View):
    model = ''
    context_obejct_name = 'task'
    success_url = reverse_lazy('tasks')












# 個人資料 =============
class Settings721(View):
    def get(self, request, *args, **kwargs):
        from .models import User, ERC721, ERC1155 
        user_addr = request.user
        user = User.objects.filter(public_address=user_addr).first()
        erc721s = ERC721.objects.filter(user_address=user_addr)
        erc1155s = ERC1155.objects.filter(user_address=user_addr)
        # erc1155_721_img =  # 從1155 id 拿到 721 img ?
        # 透過 1155 id 去取到 721 的圖片

        context ={'user':user,'erc721s':erc721s,'erc1155s':erc1155s}
        return render(request, 'app/settings721.html',context)

    def post(self, request, *args, **kwargs):
        return render(request, 'app/settings721.html')

class Settings1155(View):
    def get(self, request, *args, **kwargs):
        from .models import User, ERC721, ERC1155 
        user_addr = request.user
        user = User.objects.filter(public_address=user_addr).first()
        erc721s = ERC721.objects.filter(user_address=user_addr)
        erc1155s = ERC1155.objects.filter(user_address=user_addr)
        # erc1155_721_img =  # 從1155 id 拿到 721 img ?
        # 透過 1155 id 去取到 721 的圖片

        context ={'user':user,'erc721s':erc721s,'erc1155s':erc1155s}
        return render(request, 'app/settings1155.html',context)

    def post(self, request, *args, **kwargs):
        return render(request, 'app/settings1155.html')
# =========前端呼叫 DB

#  return user address, user 平台幣
@csrf_exempt
def getUser_info(request):
    from .models import User as user_2
    public_address = request.user
    user_obj = user_2.objects.filter(public_address=public_address).first()
    return JsonResponse({'user_info_public_address':user_obj.public_address,'user_info_platform_token':str(user_obj.platform_token)})

# user 持有的 721
@csrf_exempt
def getERC721(request):
    from .models import ERC721
    user = request.user
    user = str(user)
    erc721s = ERC721.objects.filter(user_address = user).values()
    return JsonResponse({'erc721s':list(erc721s)})

# user 持有的 1155
@csrf_exempt
def getERC1155(request):
    from .models import ERC1155
    user = request.user
    user = str(user)
    erc1155s = ERC1155.objects.filter(user_address = user).values()
    return JsonResponse({'erc1155s':list(erc1155s)})

# return pre auction 
@csrf_exempt
def getPreAuction(request):
    from .models import Auction
    auctions = Auction.objects.filter(status=2).values()
    return JsonResponse({'preAuctions':list(auctions)})

# return now auction 
@csrf_exempt
def getNowAuction(request):
    from .models import Auction
    auctions = Auction.objects.filter(status=0).values()
    return JsonResponse({'nowAuctions':list(auctions)})

# return end auction 
@csrf_exempt
def getEndAuction(request):
    from .models import Auction
    auctions = Auction.objects.filter(status=1).values()
    return JsonResponse({'endAuctions':list(auctions)})

# return pre auction 
@csrf_exempt
def getPreDirectAuction(request):
    from .models import Direct_Auction
    auctions = Direct_Auction.objects.filter(status=2).values()
    return JsonResponse({'preDirectAuctions':list(auctions)})

# return now auction 
@csrf_exempt
def getNowDirectAuction(request):
    from .models import Direct_Auction
    auctions = Direct_Auction.objects.filter(status=0).values()
    return JsonResponse({'nowDirectAuctions':list(auctions)})

# return end auction 
@csrf_exempt
def getEndDirectAuction(request):
    from .models import Direct_Auction
    auctions = Direct_Auction.objects.filter(status=1).values()
    return JsonResponse({'endDirectAuctions':list(auctions)})

# test
@csrf_exempt
def getData(request):
    if request.method == 'GET':
        data = request.GET.dict()
        print(data)
        return JsonResponse({'data':data})

@csrf_exempt
def getData1(request,pk):
    if request.method == 'GET':
        data = request.GET.dict()
        print(data)
        return JsonResponse({'data':data})

# return specific pre direct auction 
@csrf_exempt
def getSpeceficPreDirectAuction(request, pk):
    from .models import Direct_Auction
    auction = Direct_Auction.objects.filter(id=pk,status=2).values()
    return JsonResponse({'preSpecificDirectAuctions':list(auction)})

# return specific now direct auction 
@csrf_exempt
def getSpeceficNowDirectAuction(request, pk):
    from .models import Direct_Auction
    auction = Direct_Auction.objects.filter(id=pk,status=0).values()
    return JsonResponse({'nowSpecificDirectAuctions':list(auction)})

# return specific end direct auction 
@csrf_exempt
def getSpeceficEndDirectAuction(request, pk):
    from .models import Direct_Auction
    auction = Direct_Auction.objects.filter(id=pk,status=1).values()
    return JsonResponse({'endSpecificDirectAuctions':list(auction)})


# return specific pre auction 
@csrf_exempt
def getSpeceficPreAuction(request, pk):
    from .models import Auction
    auction = Auction.objects.filter(id=pk,status=2).values()
    return JsonResponse({'preSpecificAuctions':list(auction)})

# return specific now auction 
@csrf_exempt
def getSpeceficNowAuction(request, pk):
    from .models import Auction
    auction = Auction.objects.filter(id=pk,status=0).values()
    return JsonResponse({'nowSpecificAuctions':list(auction)})

# return specific end auction 
@csrf_exempt
def getSpeceficEndAuction(request, pk):
    from .models import Auction
    auction = Auction.objects.filter(id=pk,status=1).values()
    return JsonResponse({'endSpecificAuctions':list(auction)})



# create 721


# create 1155
        

# create direct_auction


# create_auction











# 募資 ===============================================以下全為募資 忽略
# CRUD 募資 

# 投資募資計畫之合約地址
# fundraising_investment_contract_address = web3.toChecksumAddress('0xa1f4b4fc9ffb9e2cdc44c151412b378274cafb8e')
# with open("fundraising_investment_contract.json") as json_file:
#     fundraising_investment_contract_abi = json.load(json_file)
# fundraising_investment_contract = web3.eth.contract(
#     address=fundraising_investment_contract_address, abi=fundraising_investment_contract_abi)

from app.contract.bytecode.FundRaisingPlan_abi import FundRaisingPlan_abi
from app.contract.bytecode.InvestmentToken_abi import InvestmentToken_abi
from app.contract.bytecode.OfficialPlan_abi import OfficialPlan_abi

# from .models import FundraisingPlan, Products
# contract_FundRaisingPlan_address  = web3.toChecksumAddress("0xda9263e2be734a643634277a872fe24cfd395f75")
# fundraising_contract = web3.eth.contract(address=contract_FundRaisingPlan_address, abi=FundRaisingPlan_abi)
# InvestmentToken_contract_address = web3.toChecksumAddress("0xa0f2aedb02ec0f93a21c1f975ecbcf98295e7894")
# contract_OfficialPlan_address  = web3.toChecksumAddress("0xdcb8848a6739a84464b702e5a6defef0d1f28f54")

#募資 contrac operation
# 創造募資計畫
def FundRaisingPlan_createFundRaisingPlan(initiator , tokenURI, contract_FundRaisingPlan_address): #創造募資憑證(token)
    initiator = Web3.toChecksumAddress(initiator)
    tokenURI = '' #可空值，可設置為ERC721的圖片
    FundRaisingPlan_token = web3.eth.contract(abi=FundRaisingPlan_abi, address=contract_FundRaisingPlan_address)
    construct_txn = FundRaisingPlan_token.functions.createFundRaisingPlan(initiator, tokenURI).buildTransaction(
                    {
                        'from': platform_address['public_address'],
                        'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                    'gasPrice': web3.eth.gas_price,
                }
                )
            # 簽名
    tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
    # transaction送出並且等待回傳
    tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    transhash = tx_receipt['transactionHash'].hex()
    print('txn_receipt')
    recepit_url = "https://goerli.etherscan.io/tx/"+transhash
    print(recepit_url)
    return recepit_url



# deploy contract -> Receive data -> 存到 DB FundraisingPlan 跟 Products
@csrf_exempt
def create_plan_for_product(request):
    if request.method == 'GET':
        user = User.objects.get(username=request.user.username)
        return render(request, "app/create-plan-for-product.html", {'user': user})
    if request.method == 'POST':
        from datetime import datetime
        '''
        Create new fundraising plan for products
        '''
        data = request.POST.dict()
        initiator = request.user
        initiator = str(initiator)
        # Deploy contract
        # issue 721 token for new plan and return id of the new token
        etherscan_url = FundRaisingPlan_createFundRaisingPlan(initiator , '', contract_FundRaisingPlan_address)
        print(f'etherscan_url:{etherscan_url}')
        # Receive Data
        initiator_addr = initiator
        title = data["title"]
        threshold_amount = int(data["threshold_amount"])
        target_amount = int(data["target_amount"])
        category = "計畫及商品"

        plan_start_date = data["fundraising_start_date"]
        plan_start_date_formatted = datetime.strptime(plan_start_date, '%Y-%m-%d')
        plan_start_date_datetime = datetime.combine(
            plan_start_date_formatted, datetime.min.time())

        plan_end_date = data["fundraising_end_date"]
        plan_end_date_formatted = datetime.strptime(plan_end_date, '%Y-%m-%d')
        plan_end_date_datetime = datetime.combine(
            plan_end_date_formatted, datetime.max.time())

        execution_start_date = data["execution_start_date"]
        execution_start_date_formatted = datetime.strptime(
            execution_start_date, '%Y-%m-%d')
        execution_start_date_datetime = datetime.combine(
            execution_start_date_formatted, datetime.min.time())

        execution_end_date = data["execution_end_date"]
        execution_end_date_formatted = datetime.strptime(
            execution_end_date, '%Y-%m-%d')
        execution_end_date_datetime = datetime.combine(
            execution_end_date_formatted, datetime.max.time())

        # revenue_standard = int(data["revenue_standard"])
        profitsharing_investor = int(data["profitsharing_investor"])
        profitsharing_initiator = int(data["profitsharing_initiator"])
        profitsharing_platform = int(data["profitsharing_platform"])
        content = data["content"]
        product_number = data["product_number"]
        image = data["cover_image"]
        liquidation_discount = data["liquidation_discount"]
        liquidation_time = data["liquidation_time"]
        # 存到 DB FundraisingPlan
        print(f'initiator_addr:{initiator_addr}, title:{title},threshold_amount:{threshold_amount},target_amount{target_amount}\nfundraising_start_date:{plan_start_date_datetime},fundraising_end_date{plan_end_date_datetime},execution_start_date:{execution_start_date_datetime},execution_end_date:{execution_end_date_datetime}\nprofitsharing_investor:{profitsharing_investor},profitsharing_initiator:{profitsharing_initiator},profitsharing_initiator:{profitsharing_initiator},profitsharing_platform:{profitsharing_platform}\ncontent:{content},product_number:{product_number},image:{image}\nliquidation_discount:{liquidation_discount},liquidation_time:{liquidation_time}')
        new_plan_form = FundraisingPlan(initiator_addr=initiator_addr,title=title,
                                        threshold_amount=threshold_amount, target_amount=target_amount, fundraising_start_date=plan_start_date_datetime,
                                        fundraising_end_date=plan_end_date_datetime, execution_start_date=execution_start_date_datetime,
                                        execution_end_date=execution_end_date_datetime,
                                        profitsharing_investor=profitsharing_investor,
                                        profitsharing_initiator=profitsharing_initiator,
                                        profitsharing_platform=profitsharing_platform, content=content,
                                        product_number=product_number, img=image,
                                        liquidation_discount=liquidation_discount, liquidation_time=liquidation_time,etherscan_url=etherscan_url,contract_address=fundraising_contract)
        new_plan_form.save()
        # plan 721 id update
        plan_db_new_id = FundraisingPlan.objects.last().id
        FundraisingPlan.objects.filter(id = plan_db_new_id).update(plan721_id=plan_db_new_id)
        print('存到 DB FundraisingPlan success')
        for i in range(int(product_number)):
            j = str(i+1)
            title = data["product"+j+"_title"]
            price = data["product"+j+"_price"]
            cost = data["product"+j+"_cost"]
            image = data["product"+j+"_image"]
            content = data["product"+j+"_content"]

            new_products = Products.objects.bulk_create([
                Products(initiator_addr=initiator_addr, title=title,
                        price=price, cost=cost, img=image, content=content, plan721_id=plan_db_new_id, product_id=j),
            ])
            print('存到 DB Products success')

        # update etherscan_url to table tx_hash
        plan = FundraisingPlan.objects.get(id=plan_db_new_id)
        plan.tx_hash = etherscan_url
        plan.save()

        return JsonResponse({'message': '募資計畫新增成功', 'etherscan_url': etherscan_url})

@csrf_exempt
def post_create_fundraising_product_plan(request):
        '''
        Create new fundraising plan for products
        '''
        from datetime import datetime
        data = request.POST.dict()
        initiator = request.user
        initiator = str(initiator)
        # Deploy contract
        # issue 721 token for new plan and return id of the new token
        etherscan_url = FundRaisingPlan_createFundRaisingPlan(initiator , '', contract_FundRaisingPlan_address)
        print(f'etherscan_url:{etherscan_url}')
        # Receive Data
        initiator_addr = initiator
        title = data["title"]
        threshold_amount = int(data["threshold_amount"])
        target_amount = int(data["target_amount"])

        plan_start_date = data["fundraising_start_date"]
        plan_start_date_formatted = datetime.strptime(plan_start_date, '%Y-%m-%d')
        plan_start_date_datetime = datetime.combine(
            plan_start_date_formatted, datetime.min.time())

        plan_end_date = data["fundraising_end_date"]
        plan_end_date_formatted = datetime.strptime(plan_end_date, '%Y-%m-%d')
        plan_end_date_datetime = datetime.combine(
            plan_end_date_formatted, datetime.max.time())

        execution_start_date = data["execution_start_date"]
        execution_start_date_formatted = datetime.strptime(
            execution_start_date, '%Y-%m-%d')
        execution_start_date_datetime = datetime.combine(
            execution_start_date_formatted, datetime.min.time())

        execution_end_date = data["execution_end_date"]
        execution_end_date_formatted = datetime.strptime(
            execution_end_date, '%Y-%m-%d')
        execution_end_date_datetime = datetime.combine(
            execution_end_date_formatted, datetime.max.time())

        # revenue_standard = int(data["revenue_standard"])
        profitsharing_investor = int(data["profitsharing_investor"])
        profitsharing_initiator = int(data["profitsharing_initiator"])
        profitsharing_platform = int(data["profitsharing_platform"])
        content = data["content"]
        product_number = data["product_number"]
        image = data["cover_image"]
        liquidation_discount = data["liquidation_discount"]
        liquidation_time = data["liquidation_time"]
        # 存到 DB FundraisingPlan
        print(f'initiator_addr:{initiator_addr}, title:{title},threshold_amount:{threshold_amount},target_amount{target_amount}\nfundraising_start_date:{plan_start_date_datetime},fundraising_end_date{plan_end_date_datetime},execution_start_date:{execution_start_date_datetime},execution_end_date:{execution_end_date_datetime}\nprofitsharing_investor:{profitsharing_investor},profitsharing_initiator:{profitsharing_initiator},profitsharing_initiator:{profitsharing_initiator},profitsharing_platform:{profitsharing_platform}\ncontent:{content},product_number:{product_number},image:{image}\nliquidation_discount:{liquidation_discount},liquidation_time:{liquidation_time}')
        new_plan_form = FundraisingPlan(initiator_addr=initiator_addr,title=title,
                                        threshold_amount=threshold_amount, target_amount=target_amount, fundraising_start_date=plan_start_date_datetime,
                                        fundraising_end_date=plan_end_date_datetime, execution_start_date=execution_start_date_datetime,
                                        execution_end_date=execution_end_date_datetime,
                                        profitsharing_investor=profitsharing_investor,
                                        profitsharing_initiator=profitsharing_initiator,
                                        profitsharing_platform=profitsharing_platform, content=content,
                                        product_number=product_number, img=image,
                                        liquidation_discount=liquidation_discount, liquidation_time=liquidation_time,etherscan_url=etherscan_url,contract_address=fundraising_contract)
        new_plan_form.save()
        # plan 721 id update
        plan_db_new_id = FundraisingPlan.objects.last().id
        FundraisingPlan.objects.filter(id = plan_db_new_id).update(plan721_id=plan_db_new_id)
        print('存到 DB FundraisingPlan success')
        for i in range(int(product_number)):
            j = str(i+1)
            title = data["product"+j+"_title"]
            price = data["product"+j+"_price"]
            cost = data["product"+j+"_cost"]
            image = data["product"+j+"_image"]
            content = data["product"+j+"_content"]

            new_products = Products.objects.bulk_create([
                Products(initiator_addr=initiator_addr, title=title,
                        price=price, cost=cost, img=image, content=content, plan721_id=plan_db_new_id, product_id=j),
            ])
            print('存到 DB Products success')

        # update etherscan_url to table tx_hash
        plan = FundraisingPlan.objects.get(id=plan_db_new_id)
        plan.tx_hash = etherscan_url
        plan.save()

        return JsonResponse({'message': '募資計畫新增成功', 'etherscan_url': etherscan_url})


@csrf_exempt
def list_plans(request):
    if request.method == 'GET':
        from .models import FundraisingPlan
        # input plan - title, status,img, 比例
        plans_pre = FundraisingPlan.objects.filter(status=0)
        plans_now = None
        plans_end = None
        context = {'plans_pre':plans_pre,'plans_now':plans_now,'plans_end':plans_end}
        return render(request, "app/list_plans.html",context)
    if request.method == 'POST':
        # pre 募資中 , now 執行中, end 結束
        from .models import FundraisingPlan
        plans_pre= request.POST.get('PRE')
        plans_now= request.POST.get('NOW')
        plans_end= request.POST.get('END')
        print(plans_pre,plans_now,plans_end)
        if plans_pre == 'PRE':
            plans_pre = FundraisingPlan.objects.filter(status=0)
        if plans_now == 'NOW':
            plans_now = FundraisingPlan.objects.filter(status=1)
        if plans_end == 'END':
            plans_end = FundraisingPlan.objects.filter(status=2)
        context = {'plans_pre':plans_pre,'plans_now':plans_now,'plans_end':plans_end}
        return render(request, "app/list_plans.html", context)


# DetailView Direct_sale 
class Detail_plans(View):
    def get(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        from .models import FundraisingPlan, Products
        from .models import User as user_2
        user_addr = request.user
        user_addr = str(user_addr)
        user = user_2.objects.filter(public_address=user_addr).first()
        plan = FundraisingPlan.objects.filter(pk=pk).first()
        print(plan.plan721_id)
        progress = round(plan.current_money /plan.threshold_amount*100, 2)
        products = Products.objects.filter(plan721_id=plan.plan721_id)
        context = {'plan':plan, 'user':user,'products':products,'progress':progress}
        return render(request,'app/detail_plans.html',context)
    def post(self, request, *args, **kwargs):
        return render(request,'app/detail_plans.html')


@csrf_exempt
def get_invest_plan_page(request, id):
    if request.method == 'GET':
        '''
        檢視投資特定計畫之頁面
        '''
        from .models import FundraisingPlan,Products
        from .models import User as user_2
        # platform_token = Member.objects.get(user_id=request.user.id).platform_token
        user_addr = request.user
        user_addr = str(user_addr)
        user = user_2.objects.filter(public_address=user_addr).first()
        # user.platform_token = platform_token
        fundraising_plan = FundraisingPlan.objects.get(id=id)
        products = Products.objects.filter(plan721_id=id)
        return render(request, "app/invest-plan.html", context={"plan": fundraising_plan, "products": products, "user": user, 'message':''})
    # - 1. 轉出平台幣
    # - 2. 發行 Token
    # - 3. 儲存資料到 DB [InvestmentRecord]
    # - 4. 更新 DB 最新金額
    # - 5. 檢查若已經到達目標金額 → a function 檢查是否可以轉成為正式計畫
    
    if request.method == 'POST':
        from .models import InvestmentRecord
        # data 要有啥 (投資價格)amount, user_address, id, product_id,product_amount
        data = request.POST.dict()
        user_addr = request.user
        user_addr = str(user_addr)
        amount = int(data['amount'])
        # 轉出平台幣 給平台、最後在分給該企劃的人員
        transferToPlatform(user_addr, data['amount'], 0)
        erc865 = call_ERC865(user_addr)
        print(f'{user_addr}:user_addr, erc865:{erc865}')
        # 發行 Token ========
        invest_token_url = issue_invest_token(data["wallet_address"], amount)
        print(f'invest_token_url:{invest_token_url}')
        # 儲存資料到 DB [InvestmentRecord] ========
        InvestmentRecord.objects.create(user_addr=user_addr,plan_id=id,amount=amount,invest_token_url=invest_token_url)
        # 更新 DB FundraisingPlan current_money 最新金額 ========
        plan = FundraisingPlan.objects.get(id=id)
        plan.current_money = plan.current_money + amount
        plan.save()
        # 檢查若已經到達目標金額 → a function 檢查是否可以轉成為正式計畫 ========
        check_if_reach_condition(id)
        return render(request, "app/invest-plan.html", context={"plan": fundraising_plan, "products": products, "user": user, 'message':'Success'})


@csrf_exempt
def issue_invest_token(to_address, amount):
    '''
    呼叫投資憑證合約，發送 865 token
    '''
    # make transaction
    to_address = Web3.toChecksumAddress(to_address)
    erc865 = web3.eth.contract(abi=InvestmentToken_abi, address=InvestmentToken_contract_address)

    construct_txn = erc865.functions.get865FromContract(to_address, amount).buildTransaction(
                    {
                        'from': platform_address['public_address'],
                        'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                    'gasPrice': web3.eth.gas_price,
                }
                )
            # 簽名
    tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
        # transaction送出並且等待回傳
    tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    transhash = tx_receipt['transactionHash'].hex()
    print('txn_receipt')
    recepit_url = "https://goerli.etherscan.io/tx/"+transhash
    print(recepit_url)
    return recepit_url


def check_if_reach_condition(id):
    '''
    檢查特定計畫是否達到轉正式計畫之條件
    '''
    plan = FundraisingPlan.objects.get(id=id)
    # 如果計畫現有投資>=目標金額 || (end_date-today == -1 and 現有投資>=門檻金額) -> 轉正式計畫
    countdown_fundraising_end = get_countdown_to_a_certain_day(plan.fundraising_end_date)
    if plan.current_money >= plan.target_amount or (countdown_fundraising_end["days"] <= -1 and plan.current_money >= plan.threshold_amount):
        to_official_plan(id)
    # 如果計畫募資到期 且 現有投資 < 門檻金額 -> close
    if countdown_fundraising_end["days"] <= -1 and plan.current_money < plan.threshold_amount:
        close_plan(id)
    # 如果計畫執行到期 -> close
    countdown_executing_end = get_countdown_to_a_certain_day(plan.execution_end_date)
    if countdown_executing_end["days"] <= -1:
        close_plan(id)

def get_countdown_to_a_certain_day(end_date):
    '''
    取得募資倒數之日、時、分數值
    '''
    difference = end_date - datetime.now()
    days, hours, minutes = difference.days, difference.seconds // 3600, difference.seconds // 60 % 60
    countdown = {
        "days": days,
        "hours": hours,
        "minutes": minutes
    }
    return countdown


def to_official_plan(id):
    '''
    轉正式計畫
    '''
    # mysql 計畫status改成 executing
    from .models import FundraisingPlan,User
    plan = FundraisingPlan.objects.get(id=id)
    plan.status = 'executing'
    # 發行正式計畫721 取得回傳的新id, initiator_ addr
    initiator_addr = plan.initiator_addr
    initiator_addr = Web3.toChecksumAddress('initiator_addr')
    OfficialPlan = web3.eth.contract(abi=OfficialPlan_abi, address=contract_OfficialPlan_address)
    construct_txn = OfficialPlan.functions.createOfficialPlan(initiator_addr, '').buildTransaction(
                    {
                        'from': platform_address['public_address'],
                        'nonce': web3.eth.getTransactionCount(platform_address['public_address']),
                    'gasPrice': web3.eth.gas_price,
                }
                )
    # 簽名
    tx_create = web3.eth.account.sign_transaction(construct_txn, platform_address['private_address'])
    # transaction送出並且等待回傳
    tx_hash = web3.eth.sendRawTransaction(tx_create.rawTransaction)
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash,timeout=600)
    transhash = tx_receipt['transactionHash'].hex()
    print('txn_receipt')
    recepit_url = "https://goerli.etherscan.io/tx/"+transhash
    print(recepit_url)
    # 轉募資中的 etherscan url  -> 正式計畫
    plan.etherscan_url = recepit_url
    plan.save()
    return recepit_url

    



@csrf_exempt
def close_plan(id):
    from .models import FundraisingPlan
    plan = FundraisingPlan.objects.filter(id=id).first()
    plan.status = 'closed'
    plan.save()
    run_profit_sharing(id)


# 分潤
# InvestmentRecord 取資料算分潤
# 紀錄 分潤紀錄 talbe
# 轉平台幣
def run_profit_sharing(plan_id):
    from .models import InvestmentRecord, FundraisingPlan
    plan = FundraisingPlan.objects.filter(id=plan_id).first()
    # 呼叫合約 轉865
    # 總收益*比例 -> 平台帳號
    # 總收益*比例 -> 發起人帳號
    # 每位投資人 總收益*比例*(投資額/總投資額)
    # [{product_id:1,
    #   investors:[
    #   {user_id:1,user_addr:'',invest_percentage:0.2},
    #   {user_id:2,user_addr:''invest_percentage:0.9}]
    #   },
    # ]
    
    profitsharing_initiator = plan.revenue * (plan.profitsharing_initiator / 100)
    profitsharing_platform = plan.revenue * (plan.profitsharing_platform / 100)
    transferToPlatform(plan.initiator_addr, profitsharing_platform, 0)
    call_ERC865(plan.initiator_addr)
    call_ERC865(platform_address['public_address'])
    investment_recrods =InvestmentRecord.objects.filter(plan_id=plan.plan721_id)
    sum = 0
    for investment_record in investment_recrods:
        sum = investment_record.amount

    profitsharing_investor = plan.revenue * (plan.profitsharing_investor / 100) # 除上買家數量 , type
    for investment_record in investment_recrods:
        transfer_tokens = (investment_record/sum) * profitsharing_investor
        transferToPlatform(plan.initiator_addr, transfer_tokens, 0)
        transferFromPlatform(investment_record.user_addr, transfer_tokens)
        call_ERC865(plan.initiator_addr)
        call_ERC865(investment_record.user_addr)



def buy_product(request):
    if request.method =='GET':
        from .models import Products
        products = Products.objects.filter(product_status=0)
        contexst = {'products',products}
        return render(request, 'app/buy_product.html',contexst)
    if request.method == 'POST':
        id = request.POST.get('id')
        print(f'商品 id(primary key in Products) {id}')
        # product owner change
        from .models import Products,FundraisingPlan
        product = Products.objects.filter(id=id).first()
        user_addr = request.user
        user_addr = str(user_addr)
        product.initiator_addr = user_addr
        # transfer platform token
        plan = FundraisingPlan.objects.filter(plan721_id=product.plan721_id).first()
        transferToPlatform(user_addr, product.price, 0)
        transferFromPlatform(plan.initiator_addr, product.price)
        call_ERC865(user_addr)
        call_ERC865(plan.initiator_addr)
        # product status change
        product.product_status = 1
        product.save()
        # plan revenue update
        plan.revenue = plan.revenue + product.price
        plan.save()
        return render(request, 'app/buy_product.html')





# 購買募資計畫商品
# DB call contract 吧
# deploy Project contract





