from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    
    # index.html
    path('', views.Login.as_view(), name='index'),
    # path('user_info/', views.user_info, name='user_info'),

    # Registration
    path('login/', views.Login.as_view(), name='login'),
    path('logout/',LogoutView.as_view(next_page='login'), name='logout'),  # next_page --> change where the user goes, here go to login
    path('login/nonce/', views.signNonce, name='signNonce'),

    # Settings
    path('settings721/', views.Settings721.as_view(),name = 'settings721'),
    path('settings1155/', views.Settings1155.as_view(),name = 'settings1155'),

    # Platform token
    path('buy-erc865/', views.Create_erc865.as_view(), name='buy-erc865'), # step 1
    path('buy-erc865/nonce/', views.signNonce, name = 'signNonce'), # step 2
    path('buy-erc865/sign_res/', views.sign_res, name='sign_res'), # step 3
    path('buyERC865/', views.buyERC865, name='buyERC86'), # step 4
    path('getAbiBytecode/', views.getAbiBytecode), # step 5
    path('frontend/return/', views.PaymentReturnView.as_view(), name='tx_return'), # step 6 
    
    # create 721 1155
    path('create-NFT/', views.Create_NFT.as_view(), name='Create_NFT'), # step 1 
    path('create-NFT721/', views.Create_NFT721.as_view(), name='Create_NFT721'), # step 2
    path('create-NFT1155/', views.Create_NFT1155.as_view(), name='Create_NFT1155'), # step 2 
    path('create-NFT-result/', views.Create_NFT_Result.as_view(), name='Create_NFT_Result'), # step 3
    path('721_detail/<int:pk>', views.Detail_NFT721.as_view(), name='detail-721'),
    # How to sell
    path('choose-how-sell/',views.How_to_sell.as_view() ,name = 'how_to_sell'),
    # How to buy NFT 
    path('choose-how-to-buy-nft/',views.Buy_NFT.as_view() ,name = 'buy_nft'),
    # 1. Auction
    path('sale/create-auction',views.Create_auction.as_view() ,name = 'create-auction'),
    path('sale/create-auction/result',views.Create_auction_result.as_view() ,name = 'create-auction-result'),
    path('sale/list-auction',views.List_auction.as_view() ,name = 'list-auction'),
    path('auction_time/',views.auction_time ,name = 'auction-time'),
    path('sale/detail-auction/<int:pk>',views.Detail_auction.as_view() ,name = 'detail-auction'),
    path('confirm_auction/',views.confirm_auction ,name = 'confirm_auction'),
    path('confirm_buy_it_now/',views.confirm_buy_it_now ,name = 'confirm_buy_it_now'),
    # path('lastest_it_now/',views.lastest_it_now ,name = 'lastest_it_now'),
    path('auction_time1/',views.getDatetime ,name = 'getDatetime'),

    # 2. Direct sale
    # user 輸入 form --> 確認 form 沒有問題 --> 鎖定藝術品 --> [如果有人購買 erc1155交易藝術品 , erc865交易平台幣] or [無人購買退還藝術品]
    path('sale/create-direct-sale/', views.Create_direct_sale.as_view(), name='create-direct-sale'),
    path('sale/list-direct-sale/', views.List_direct_sale.as_view(), name='list-direct-sale'),
    path('sale/detail-direct-sale/<int:pk>', views.Detail_direct_sale.as_view(), name='detail-direct-sale'),
    path('sale/update-direct-sale/', views.Update_direct_sale.as_view(), name='update-direct-sale'),
    path('sale/delete-direct-sale/', views.Delete_direct_sale.as_view(), name='delete-direct-sale'),
    path('direct_confirm_buy_it_now/', views.direct_confirm_buy_it_now, name='direct_confirm_buy_it_now'),
    path('confirm_buy_it_now_direct/', views.confirm_buy_it_now_direct, name='confirm_buy_it_now_direct'),

    #圖文作家
    path('writer_all/', views.Writer_all.as_view(), name='writer_all'),
    path('writer_subscribe/', views.Writer_subscribe.as_view(), name='writer_subscribe'),

    # GET 相關 api ========
    # 須在登陸情況下使用的 api
    path('api/getUser_info/', views.getUser_info, name='getUser_info'),
    # 須在登陸情況下使用的 api
    path('api/getERC721/', views.getERC721, name='getERC721'),
    # 須在登陸情況下使用的 api
    path('api/getERC1155/', views.getERC1155, name='getERC1155'),
    # 以下為不須在登陸情況下使用的 api
    path('api/getPreAuction/', views.getPreAuction, name='getPreAuction'),
    path('api/getNowAuction/', views.getNowAuction, name='getNowAuction'),
    path('api/getEndAuction/', views.getEndAuction, name='getEndAuction'),
    path('api/getPreDirectAuction/', views.getPreDirectAuction, name='getPreDirectAuction'),
    path('api/getNowDirectAuction/', views.getNowDirectAuction, name='getNowDirectAuction'),
    path('api/getEndDirectAuction/', views.getEndDirectAuction, name='getEndDirectAuction'),
    # GET 相關 api 需要 specific id
    path('api/getData/', views.getData, name='getData'),
    path('api/getData1/<str:pk>', views.getData1, name='getData1'),
    
    path('api/getSpeceficPreDirectAuction/<str:pk>', views.getSpeceficPreDirectAuction, name='getPreDirectAuction'),
    path('api/getSpeceficNowDirectAuction/<str:pk>', views.getSpeceficNowDirectAuction, name='getNowDirectAuction'),
    path('api/getSpeceficEndDirectAuction/<str:pk>', views.getSpeceficEndDirectAuction, name='getEndDirectAuction'),
    
    path('api/getSpeceficPreAuction/<str:pk>', views.getSpeceficPreAuction, name='getSpeceficPreAuction'),
    path('api/getSpeceficNowAuction/<str:pk>', views.getSpeceficNowAuction, name='getSpeceficNowAuction'),
    path('api/getSpeceficEndAuction/<str:pk>', views.getSpeceficEndAuction, name='getSpeceficEndAuction'),

    # POST 相關 API 都需要在錢包登錄下使用、且須 pass 相關 data
    
    

    # Fundraising
    path('create-plan-for-product/', views.create_plan_for_product,name='create_plan_for_product'),
    path('create-fundraising-product-plan/',views.post_create_fundraising_product_plan),
    path('list-fundraising-product-plan/',views.list_plans,name='list-fundraising-product-plan'),
    path('detail-fundraising-product-plan/<int:pk>',views.Detail_plans.as_view(),name='detail-fundraising-product-plan'),
    path('invest-plan/<id>', views.get_invest_plan_page, name='invest-plan'),
    path('buy-product/', views.buy_product, name='buy-product'),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

