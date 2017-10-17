<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Welcome to Barikoi, {{$person_name}}!</title>
    <!-- 
    The style block is collapsed on page load to save you some scrolling.
    Postmark automatically inlines all CSS properties for maximum email client 
    compatibility. You can just update styles here, and Postmark does the rest.
    -->

<link rel="stylesheet" type="text/css" href="{{URL::asset('assets/welcome.css')}}">
  </head>
  <body>
    
    <table class="email-wrapper" width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td align="center">
          <table class="email-content" width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td class="email-masthead" style="font-family:Arial, 'Helvetica Neue', Helvetica, sans-serif;padding:25px 0;" align="center">
                <a href="https://barikoi.com" class="email-masthead_name" style="color:#FFFFFF;font-family:Arial, 'Helvetica Neue', Helvetica, sans-serif;font-size:16px;text-decoration:none;">
                  <img src="http://i.imgur.com/yMVpGJK.png" alt="yMVpGJK.png"></a>
                </td>
              </tr>
            <!-- Email Body -->
            <tr>
              <td class="email-body" width="100%" cellpadding="0" cellspacing="0">
                <table class="email-body_inner" align="center" width="570" cellpadding="0" cellspacing="0">
                  <!-- Body content -->
                  <tr>
                    <td class="content-cell">
                      <h1>Welcome, {{$person_name}}!</h1>
                      <p>Thanks for joining Barikoi Community. We’re thrilled to have you on board.</p>
                      <p>If you have any questions, feel free to <a href="mailto:{{barikoicode<?php echo urldecode('%40')?>gmail.com}}">email us</a>. (We're lightning quick at replying.) Find us on <a href="https://www.facebook.com/barikoii">Facebook</a>.
                      <p>Thanks,
                        <br>Barikoi Team</p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td>
                <table class="email-footer" align="center" width="570" cellpadding="0" cellspacing="0">
                  <tr>
                    <td class="content-cell" align="center">
                      <p class="sub align-center">&copy; 2017 Barikoi. All rights reserved.</p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>