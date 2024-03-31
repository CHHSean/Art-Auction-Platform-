from django import forms
from .models import ERC721, ERC1155,Auction,Direct_Auction

TIME_INTERVAL = [('7','7'),('14','14'),('28','28')]

# Create 721
class Create721Form(forms.ModelForm):
    
    class Meta:
        model = ERC721
        fields = ('user_address','erc721_id','erc721_name','symbol','img')
        labels = {
            'erc721_id' : 'ERC721 Id',
            'erc721_name': 'ERC721 Name',
            'symbol': 'symbol',
            'img': 'img'
        }
        widgets = {
            'user_address': forms.TextInput(attrs={'id': 'user_address_721'}),
            'erc721_id': forms.TextInput(attrs={'id': 'erc721_id'}),
            'erc721_name': forms.TextInput(attrs={'id': 'erc721_name'}),
            'symbol': forms.TextInput(attrs={'id': 'symbol_721'}),
            'img': forms.FileInput(attrs={'class': 'form-control-file'})
        }



# Create 1155
class Create1155Form(forms.ModelForm):
    
    class Meta:
        model = ERC1155
        fields = ('user_address', 'erc721_id', 'erc1155_id','erc1155_name', 'amount')
        labels = {
            'user_address': 'user_address',
            'erc1155_name': 'erc1155_name',
            'amount':'amount'
        }
        widgets = {
            'user_address': forms.TextInput(attrs={'id': 'user_address_1155'}),
            'erc721_id': forms.TextInput(attrs={'id': 'erc721_id'}),
            'erc1155_id': forms.TextInput(attrs={'id': 'erc1155_id'}),
            'erc1155_name': forms.TextInput(attrs={'id': 'erc1155_name'}),
            'amount': forms.TextInput(attrs={'id': 'amount'}),
        }


class CreateAuctionForm(forms.ModelForm):
    
    class Meta:
        model = Auction
        fields = ('seller_addr', 'category','product_id', 'title','content','amount','buy_it_now','starting_price','add_price','auction_time')
        labels = {
            'seller_addr': 'user_address',
            'category' : 'NFT 種類',
            'product_id': 'Product ID',
            'title' : '標題',
            'content': '內文',
            'amount': '販售數量',
            'buy_it_now':'設定一口價',
            'starting_price':'起標價',
            'add_price':'規定每次加價價格',
            'auction_time':'拍賣時間(day)'
        }
        labels = {
            'user_address': 'user_address',
            'erc1155_name': 'erc1155_name',
            'amount':'amount'
        }
        widgets = {
            'seller_addr': forms.TextInput(attrs={'id': 'seller_addr_auction'}),
            'category': forms.Select(attrs={'id': 'category_auction'}), # input 特別
            'product_id': forms.TextInput(attrs={'id': 'product_id_auction'}),
            'title': forms.TextInput(attrs={'id': 'title_auction'}),
            'content': forms.TextInput(attrs={'id': 'content_auction'}),
            'buy_it_now': forms.NumberInput(attrs={'id': 'buy_it_now_auction'}),
            'amount': forms.NumberInput(attrs={'id': 'amount_auction'}),
            'starting_price': forms.NumberInput(attrs={'id': 'starting_price_auction'}),
            'add_price': forms.NumberInput(attrs={'id': 'add_price_auction'}),
            'auction_time': forms.TextInput(attrs={'id': 'auction_time_auction'}),
        }



class Create_direct_saleForm(forms.ModelForm):

    class Meta:
        model = Direct_Auction
        fields = ('seller_addr', 'category','product_id', 'title','content','amount','price','auction_time')
        labels = {
            'seller_addr': 'user_address',
            'category' : 'NFT 種類',
            'product_id': 'Product ID',
            'title' : '標題',
            'content': '內文',
            'amount': '販售數量',
            'price':'販售價格',
            'auction_time':'拍賣時間(day)'
        }
        widgets = {
            'seller_addr': forms.TextInput(attrs={'id': 'seller_addr_direct_auction'}),
            'category': forms.Select(attrs={'id': 'category_direct_uction'}), #input 特別
            'product_id': forms.TextInput(attrs={'id': 'product_id_direct_auction'}),
            'title': forms.TextInput(attrs={'id': 'title_direct_auction'}),
            'content': forms.TextInput(attrs={'id': 'content_direct_auction'}),
            'amount' : forms.NumberInput(attrs={'id': 'amount_direct_auction'}),
            'price': forms.NumberInput(attrs={'id': 'price_direct_auction'}),
            'auction_time': forms.NumberInput(attrs={'id': 'auction_time_direct_auction'}),
        }

