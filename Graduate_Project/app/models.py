from pyexpat import model
from statistics import mode
from django.db import models
from django.contrib.auth.models import User

NFT_CATEGORIES = ((0,'721'),(1,'1155'))
AUCTION_STATUS =((0,'拍賣中'),(1,'結束拍賣'),(2,'即將拍賣'))
FUNDRAISINGPLAN_STATUS =((0,'募資中'),(1,'執行計畫'),(2,'關閉'))
PRODUCT_STATUS = ((0,'販售中'),(1,'非販售中'))
class User(models.Model):
    user_name = models.OneToOneField(User, on_delete=models.CASCADE) # User_Name, email, password
    public_address = models.CharField(max_length=42)
    platform_token = models.FloatField(default=0)

    def __str__(self):
        return 'user_name:{} |  platform_token:{}'.format(self.user_name, self.platform_token)

class ERC721(models.Model):
    user_address = models.CharField(max_length=42)
    erc721_id =  models.CharField(max_length=250,blank=False) # 721 id
    erc721_name = models.CharField(max_length=250)
    symbol = models.CharField(max_length=250)
    img = models.ImageField(upload_to='image/', blank=False, null=False)
    contract_address = models.CharField(max_length=42, null=True, blank=True)
    etherscan_url = models.CharField(max_length=2048, null=True, blank=True)

    def __str__(self):
        return '持有人地址:{}'.format(self.user_address)


class ERC1155(models.Model):
    user_address = models.CharField(max_length=42)
    erc721_id = models.CharField(max_length=42)
    erc1155_id = models.CharField(max_length=250)
    erc1155_name = models.CharField(max_length=250)
    img = models.ImageField(upload_to='image/', blank=False, null=False)
    amount = models.IntegerField()
    etherscan_url = models.CharField(max_length=2048, null=True, blank=True)

    def __str__(self):
        return '持有人地址:{} |  erc721_id:{} |erc1155_id:{} |  erc1155_name:{}'.format(self.user_address,self.erc721_id,self.erc1155_id,self.erc1155_name)

class Auction(models.Model):
    img = models.ImageField(upload_to='image/', blank=False, null=False)
    seller_addr = models.CharField(max_length=42)
    category = models.IntegerField(choices=NFT_CATEGORIES) # 0\false -> 721 , 1\true -> 1155
    product_id = models.CharField(max_length=250)
    title = models.CharField(max_length=250)
    content = models.CharField(max_length=250)
    amount = models.IntegerField()
    buy_it_now = models.DecimalField(decimal_places=2,max_digits=50,null=True) # 一口價
    starting_price = models.DecimalField(decimal_places=2,max_digits=50) # 起標價
    add_price = models.DecimalField(decimal_places=2,max_digits=50) # 每次加價數價格
    latest_price = models.DecimalField(decimal_places=2,max_digits=50,null=True,blank=True, default=0) # 最高價格
    auction_time = models.DecimalField(decimal_places=2,max_digits=50) # 競拍時間
    created_at = models.DateTimeField(auto_now_add=True) # 創建時間
    starting_time = models.DateTimeField(null=True) # 上架的時間
    updated_at = models.DateTimeField(auto_now=True) # update 時間
    status =  models.IntegerField(choices=AUCTION_STATUS,default=2) # 狀態
    contract_address = models.CharField(max_length=42, null=True, blank=True) # auction address
    etherscan_url = models.CharField(max_length=2048, null=True, blank=True) # auction url
    status_deploy = models.BooleanField(default=False)

class Direct_Auction(models.Model):
    img = models.ImageField(upload_to='image/', blank=False, null=False)
    seller_addr = models.CharField(max_length=42)
    category = models.IntegerField(choices=NFT_CATEGORIES) # 0\false -> 721 , 1\true -> 1155
    product_id = models.CharField(max_length=250)
    title = models.CharField(max_length=250)
    content = models.CharField(max_length=250)
    starting_time = models.DateTimeField(null=True) # 上架的時間
    amount = models.IntegerField()
    price = models.DecimalField(decimal_places=2,max_digits=50)
    auction_time = models.DecimalField(decimal_places=2,max_digits=50) # 直拍時間
    created_at = models.DateTimeField(auto_now_add=True) # 創建時間
    status =  models.IntegerField(choices=AUCTION_STATUS,default=2) # 狀態 0 -> 拍賣中，1->結束拍賣，2-> 即將拍賣(不一定要)
    contract_address = models.CharField(max_length=42, null=True, blank=True) # auction address
    etherscan_url = models.CharField(max_length=2048, null=True, blank=True) # auction url

# 每次出價重新紀錄
class Auction_Record(models.Model):
    seller_addr = models.CharField(max_length=42) # buyer address
    auction_id = models.CharField(max_length=250)
    bid_price = models.DecimalField(decimal_places=2,max_digits=50)
    bid_time = models.DateTimeField(auto_now_add=True)

from django.utils import timezone
# 募資計畫
# class FundraisingPlan(models.Model):
#     plan721_id = models.CharField(max_length=255) # 募資計畫 721
#     initiator_addr = models.CharField(max_length=42) # foreign key
#     title = models.CharField(max_length=255) # 募資標題
#     threshold_amount = models.DecimalField(decimal_places=2,max_digits=50,null=True) # 門檻金額
#     target_amount = models.DecimalField(decimal_places=2,max_digits=50,null=True) # 目標金額
#     # 計畫募資期間
#     fundraising_start_date = models.DateTimeField(default=timezone.now, blank=True, null=True)
#     fundraising_end_date = models.DateTimeField(default=timezone.now, blank=True, null=True)
#     # 計畫執行期間
#     execution_start_date = models.DateTimeField(default=timezone.now, blank=True, null=True)
#     execution_end_date = models.DateTimeField(default=timezone.now, blank=True, null=True)
#     # 分潤條件 投資人 發起人 平台
#     profitsharing_investor = models.IntegerField()
#     profitsharing_initiator = models.IntegerField()
#     profitsharing_platform = models.IntegerField()
#     content = models.CharField(max_length=255) # 計畫內容
#     # ? 目前已經募資到的金額?
#     current_money = models.IntegerField(default=0)
#     # 預計募資之商品
#     product_number = models.IntegerField(default=0)
#     # 募資封面
#     img = models.CharField(max_length=2048, null=True, blank=True)
#     status = models.IntegerField(choices=FUNDRAISINGPLAN_STATUS,default=0) # 募資狀態
#     # Contract
#     etherscan_url = models.CharField(max_length=2048, null=True, blank=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     # 拍賣執行天數 
#     liquidation_time = models.IntegerField(default=30)
#     # product_ number
#     product_number = models.IntegerField(default=0)
    
#     created_at = models.DateTimeField(auto_now_add=True) # 創建時間
#     # 發起人買回商品之折扣數 
#     liquidation_discount = models.IntegerField(default=0)
#     contract_address = models.CharField(max_length=42, null=True, blank=True) # 募資 address
#     etherscan_url = models.CharField(max_length=2048, null=True, blank=True)
#     revenue = models.DecimalField(decimal_places=2,max_digits=50,null=True)



# class Products(models.Model):
#     initiator_addr = models.CharField(max_length=42) # initiator_addr or owner
#     title = models.CharField(max_length=50) # 商品名稱
#     plan721_id = models.CharField(max_length=255) # foreign key
#     price = models.DecimalField(decimal_places=2,max_digits=50,null=True)  # 預計售價
#     product_id = models.IntegerField(default=0) # product id ? 1155 ?
#     content = models.CharField(max_length=255) # product description
#     issued_amount = models.IntegerField(default=0)  # 發行數量
#     sold_amount = models.IntegerField(default=0) # 販賣數量
#     cost = models.DecimalField(decimal_places=2,max_digits=50,null=True) # 預計成本
#     img = models.CharField(max_length=2048, null=True, blank=True) # 商品圖片
#     contract_address = models.CharField(max_length=42, null=True, blank=True) # 募資 address
#     etherscan_url = models.CharField(max_length=2048, null=True, blank=True) # 創建的 etherscan url
#     product_1155_id = models.CharField(max_length=255, default="")
#     product_status = models.IntegerField(choices=PRODUCT_STATUS,default=1) # 0 販售中 , 1 -> 非返售中

#     def __str__(self):
#         return '發起人:{} plan721_id:{}'.format(self.initiator_addr,self.plan721_id)


# class InvestmentRecord(models.Model):
#     user_addr = models.CharField(max_length=42) 
#     plan_id = models.IntegerField()
#     product_id = models.IntegerField() # product id 拿掉
#     amount = models.DecimalField(decimal_places=2,max_digits=50,null=True) # 投資價格
#     etherscan_url = models.CharField(max_length=2048, null=True, blank=True) # 拿掉
#     created_at = models.DateTimeField(auto_now_add=True)
#     type = models.CharField(max_length=255, default="invest") # 拿掉
#     invest_token_url = models.CharField(max_length=2048, null=True, blank=True)

    # class Meta:
    #     db_table = "investment_record"

# 銷售 buyer 紀錄
# class SalesRecord(models.Model):
#     buyer_addr = models.CharField(max_length=42)
#     plan721_id = models.IntegerField()
#     product1155_id = models.IntegerField()
#     amount = models.IntegerField()
#     etherscan_url = models.CharField(max_length=2048, null=True, blank=True)
#     created_at = models.DateTimeField(auto_now_add=True)


#  分潤紀錄
# class ProfitSharingRecord(models.Model):
#     user_addr = models.CharField(max_length=42)
#     plan721_id = models.IntegerField()
#     product = models.ForeignKey(Products, on_delete=models.CASCADE)
#     profit = models.IntegerField()
#     identity = models.CharField(max_length=255, default="")
#     etherscan_url = models.CharField(max_length=255, default="")
#     created_at = models.DateTimeField(auto_now_add=True)

#     class Meta:
#         db_table = "profit_sharing_record"
