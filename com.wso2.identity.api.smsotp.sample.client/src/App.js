import './App.css';
import Button from "@material-ui/core/Button";
import qs from "qs";
import React, { useState } from "react";

const axios = require('axios').default;

//start authentication API call
async function generateOTP(userId, setShowOtpForm) {
    const body = {
        "userId": userId,
    }

    let headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic YWRtaW46YWRtaW4='
    };

    try {
        let response = await axios.post('https://localhost:9443/api/identity/sms-otp/v1/smsotp/generate', body,
            {headers})
        if (response.status == 200) {
            setShowOtpForm(true);
            return response.data;
        }
    } catch (err) {
        console.log(err);
        alert(err.response.data.description);
    }

};

//finish authentication API call
async function validateOTP(userId, transactionId, otp) {

    let headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'Authorization': 'Basic X3VBdE5EcEFQazl2UUxEYkE3UktvYkdkSnRrYTo0d1B2VXAwcldXRTdsMEtiek95WmVidFBjeGdh'
    };

    const body = {
            "grant_type":"smsotp",
            "userId": userId,
            "transactionId": transactionId,
            "otp": otp,
            "scope":"openid"
    }

    try {
        let res = await axios.post('https://localhost:9443/oauth2/token', qs.stringify(body), { headers });
        if (res.status == 200) {
            console.log(res.data);
            alert("Authentication Successful!");
            return res;
        }
    } catch (err) {
        alert(err);
    }
}


function App() {

  const [userId, setUserId] = useState('');
  const [otp, setOtp] = useState('');
  const [transactionId, setTransactionId] = useState('');
  const [showOtpForm, setShowOtpForm] = useState(false);

  const handleSendOtp = async (event) => {
    event.preventDefault();
    // Call an API endpoint to send the OTP to the user
    let response = await generateOTP(userId, setShowOtpForm);
    setTransactionId(response.transactionId);
    console.log(`Sending OTP to user ${userId}`);
  };

  const handleVerifyOtp = async (event) => {
    event.preventDefault();
    // Call an API endpoint to verify the OTP
    await validateOTP(userId, transactionId, otp);
  };

  const handleUserIdChange = (event) => {
    setUserId(event.target.value);
  };

  const handleOtpChange = (event) => {
    setOtp(event.target.value);
  };

  const handleBack = () => {
    setShowOtpForm(false);
    setUserId('');
    setOtp('');
    setTransactionId('');
  };

  if (!showOtpForm) {
    return (
    <div className="App" style={{display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh'}}>
      <form className="form" onSubmit={handleSendOtp}>
      <div className="form-field">
        <label htmlFor="userId">User ID:</label>
        <input className="input" type="text" id="userId" name="userId" value={userId} onChange={handleUserIdChange}
          required />
        </div>
        <Button className="button" type="submit" variant="contained" color="primary" style={{margin: '10px'}}> Send
        OTP</Button>
      </form>
      </div>
    );
  }

  return (
  <div className="App" style={{display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh'}}>
    <form className="form" onSubmit={handleVerifyOtp}>
    <div className="form-field">
      <label htmlFor="otp">Enter the OTP:</label>
      <div style={{ display: 'flex', alignItems: 'center' }}>
      <input className="input" type="text" id="otp" name="otp" value={otp} onChange={handleOtpChange} maxLength={6}
        required style={{ marginRight: '10px' }} />
       <button type="button" style={{ fontSize: '20px' }} onClick={handleSendOtp}>↺</button>
       </div> </div>
      <div className="button-container" style={{ display: 'flex', justifyContent: 'center' }}>
      <Button className="button" variant="contained" color="primary" style={{margin:
                          '10px'}} type="button" onClick={handleBack}>Back</Button>
      <Button className="button" type="submit" variant="contained" color="primary" style={{margin:
      '10px'}}>Verify</Button>
      </div>
    </form>
    </div>
  );
}

export default App;


