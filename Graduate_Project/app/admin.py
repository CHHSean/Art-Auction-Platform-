from django.contrib import admin
from .models import User, ERC721, ERC1155,Auction,Direct_Auction,Auction_Record


admin.site.register(User)
admin.site.register(ERC721)
admin.site.register(ERC1155)
admin.site.register(Auction)
admin.site.register(Direct_Auction)
admin.site.register(Auction_Record)
# admin.site.register(FundraisingPlan)
# admin.site.register(Products)