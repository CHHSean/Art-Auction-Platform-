web3 = new Web3(window.ethereum);


    let nonceToSign = "";

    // connect to metamask - 1
    $("#connectMetaMask").click(function(){
        console.log('#connectMetaMask');
        ethereum.request({ method:"eth_requestAccounts"}).then(buttonStatus_Connected(), getNonce(),).catch(buttonStatus_Disconnected);
    })
    // Django 後端 signNonce function 傳給前端（簽章亂數），用JsonResponse 傳給 JS 然後用 Ajax 處理 - 3
    function getNonce(){
        $.getJSON("nonce",function (result){
            nonceToSign = result.nonce;
        })
    }
    

    function buttonStatus_Connected(){
        document.getElementById('metamaskLogin').disabled=false;　// 變更欄位為可用
        document.getElementById('connectMetaMask').disabled=true;　// 變更欄位為禁用
    }
    
    function buttonStatus_Disconnected(){
        document.getElementById('connectMetaMask').disabled=false;　// 變更欄位為可用
        document.getElementById('metamaskLogin').disabled=true;　// 變更欄位為禁用
    }

     // submit form 丟到 Django 後端 -4
    function loginForm(address, signature, message){
        //console.log(address, signature, message)
        $("#account").val(address);
        $("#signature").val(signature);
        $("#message").val(message);
        $("#loginForm").submit();
    }


    // 請使用者簽署亂數+ 特定文字 - 2
    // 再把 addr(使用者 address), String(result) (把簽署出的簽章轉乘 Str)
    // 把這三個塞到挖出的隱形 input 後 submit form
    $("#metamaskLogin").click(function () {
        msgToSign = "為認證您為該地址的合法持有人，我們將要求您簽署這串文字，進行簽章驗證" + nonceToSign
        ethereum.request({method: 'eth_requestAccounts'}).then(
                web3.eth.getAccounts()
                .then(result=>addr = result)
                .then(result =>
                    web3.eth.personal.sign(msgToSign, web3.utils.toChecksumAddress(result[0]))
                    .then(result => loginForm(addr,String(result),msgToSign))));
                        // .then(result => test_1(addr,String(result),msgToSign))));
    })
    