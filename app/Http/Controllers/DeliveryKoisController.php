<?php namespace App\Http\Controllers;


use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\DeliveryKoi;
use App\DeliveryMan;
use App\User;
use OneSignal;
use DB;
use Carbon\Carbon;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Client;
class DeliveryKoisController extends Controller {

  //  const MODEL = "App\DeliveryKoi";

    //use RESTActions;
    //======================== Customer/User Part ===============

    public function generateRandomString($length = 10) {
      $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      $charactersLength = strlen($characters);
      $randomString = '';
      for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
      }
      return $randomString;
    }
    public function PlaceOrder(Request $request)
    {
      $verification_code = $this->generateRandomString(6);
      $order = DeliveryKoi::create($request->all()+['user_id'=> $request->user()->id,'sender_name'=> $request->user()->name,'sender_number'=>$request->user()->phone,'delivery_fee'=> ($request->product_weight*25)+60, 'verification_code'=>$verification_code]);

      $message = ' '.$request->user()->name.' Requested a Delivery';
      $channel = 'delivery';
      $data = array(
           'channel'     => $channel,
           'username'    => 'tayef',
           'text'        => $message

       );
      //Slack Webhook : notify
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
    // Make your message
      $message_string = array('payload' => json_encode($data));
      //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message_string);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);
    //  $this->testsms($request->user()->name,$request->user()->phone);

      return response()->json(['message' => 'order created']);
    }
    // PlaceOrder from Dashboard
    public function PlaceOrderDashBoard(Request $request)
    {
      $verification_code = $this->generateRandomString(6);
      $order = DeliveryKoi::create($request->all()+['user_id'=> $request->user()->id,'delivery_fee'=> ($request->product_weight*25)+60, 'verification_code'=>$verification_code]);

      $message = ' '.$request->user()->name.' Requested a Delivery';
      $channel = 'delivery';
      $data = array(
           'channel'     => $channel,
           'username'    => 'tayef',
           'text'        => $message

       );
      //Slack Webhook : notify
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
    // Make your message
      $message_string = array('payload' => json_encode($data));
      //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message_string);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);
    //  $this->testsms($request->user()->name,$request->user()->phone);

      return response()->json(['message' => 'order created']);
    }

    public function OrderByID($id)
    {
      $OrderNumber = DeliveryKoi::findOrFail($id);

      return $OrderNumber->toJson();
    }

    public function updateOrder(Request $request, $id)
    {
      $updateOrder = DeliveryKoi::findOrFail($id);
      if ($request->has('pick_up')) {
        $updateOrder->pick_up = $request->pick_up;
      }
      if ($request->has('drop_off')) {
        $updateOrder->drop_off = $request->drop_off;
      }
      if ($request->has('drop_off_lon')) {
        $updateOrder->drop_off_lon = $request->drop_off_lon;
      }
      if ($request->has('drop_off_lat')) {
        $updateOrder->drop_off_lat = $request->drop_off_lat;
      }
      if ($request->has('pick_up_date')) {
        $updateOrder->pick_up_date = $request->pick_up_date;
      }
      if ($request->has('preffered_time')) {
        $updateOrder->preffered_time = $request->preffered_time;
      }
      if ($request->has('product')) {
        $updateOrder->product = $request->product;
      }
      if ($request->has('product_weight')) {
        $updateOrder->product_weight = $request->product_weight;
      }
      if ($request->has('product_price')) {
        $updateOrder->product_price = $request->product_price;
      }
      if ($request->has('receivers_name')) {
        $updateOrder->receivers_name = $request->receivers_name;
      }
      if ($request->has('receivers_number')) {
        $updateOrder->receivers_number = $request->receivers_number;
      }

      $updateOrder->save();

      return response()->json(['message'=>'Order updated']);
    }
    // Get orders by User ID
    public function UserOrders(Request $request)
    {
      $id = $request->user()->id;
      $UserOrders = DeliveryKoi::where('user_id', $id)->orderBy('created_at','desc')->get();

      return  $UserOrders->toJson();
    }

    public function OrderCancelled($id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      $Order->delivery_status = 4;
      $Order->save();



      return response()->json(['message'=>'Delivery ID number '.$id.' has been Cancelled']);
    }

    // ====== = ===== == ==== Marchent / Logistics companies part

    public function logisticsAnalytics(Request $request)
    {
      $id = $request->user()->id;
      $UserOrders = DeliveryKoi::where('user_id', $id)->count();
      $deliveryMan =  DeliveryMan::where('company_id',$id)->count();
      $totalDelivered = DeliveryKoi::where('user_id', $id)->where('delivery_status',3)->count();
      $totalReturned = DeliveryKoi::where('user_id', $id)->where('delivery_status',5)->count();
      $totalEarned = DeliveryKoi::where('user_id', $id)->where('delivery_status',3)->sum('delivery_fee');
      $totalDeliveredWorth = DeliveryKoi::where('user_id', $id)->where('delivery_status',3)->sum('product_price');
      return  response()->json(['Total Orders' => $UserOrders,
      'Total Delivery Man' => $deliveryMan,
      'Total Delivered' => $totalDelivered,
      'Total Returned' => $totalReturned,
      'Earned' => $totalEarned,
      'Total Delivered Worth' => $totalDeliveredWorth

    ]);
    }

    //================== Admin Part============================

    public function getAllOrder()
    {
      //$now = Carbon::now()->toDateString();
      $AllOrder = DeliveryKoi::all();
      return $AllOrder->toJson();
    //return $now;
    }
    public function getBookedOrder()
    {
      $Order =  DeliveryKoi::where('delivery_status',1)->get();
      return $Order->toJson();
    }
    public function getCancelledOrder()
    {
      $Order =  DeliveryKoi::where('delivery_status',4)->get();
      return $Order->toJson();
    }
    public function getOngoingOrder()
    {
      $Order =  DeliveryKoi::where('delivery_status',2)->get();
      return $Order->toJson();
    }
    public function getDeliveredOrder()
    {
      $Order =  DeliveryKoi::where('delivery_status',3)->get();
      return $Order->toJson();
    }

    public function DeleteOrder($id)
    {
      $UserOrders = DeliveryKoi::findOrFail($id);
      $UserOrders->delete();
      return response()->json(['message'=>'Order Deleted']);;
    }

    public function AssignOrderByAdmin(Request $request)
    {
       $id = $request->id;
       $userId = $request->user_id;
       $driver = User::findOrFail($userId);
       $AcceptOrder = DeliveryKoi::findOrFail($id);
       $AcceptOrder->delivery_mans_id = $driver->id;
       $AcceptOrder->delivery_man_name = $driver->name;
       $AcceptOrder->delivery_man_number = $driver->phone;
       $AcceptOrder->delivery_status = 1;
       $AcceptOrder->save();
       return response()->json(['message'=>'Order Assigned']);

    }
    public function getDeliveryMan(Request $request)
    {
      $deliveryman = DeliveryMan::where('company_id',$request->user()->id)->get(['delivery_man_id']);
      $user = User::whereIn('id',$deliveryman)->get();
     return response()->json($user);

    }

    //=================== Delivery Man Part ==================
    public function AcceptOrder(Request $request, $id)
    {
      if ($request->user()->userType == 5 || $request->user()->userType == 1) {
        $AcceptOrder = DeliveryKoi::findOrFail($id);
        $AcceptOrder->delivery_mans_id = $request->user()->id;
        $AcceptOrder->delivery_man_name = $request->user()->name;
        $AcceptOrder->delivery_man_number = $request->user()->phone;
        $AcceptOrder->delivery_status = 1;
        $AcceptOrder->save();

        $to = $AcceptOrder->receivers_number;
        $token = "7211aa139c9eaaa7184cead6c1bc7bee";
        $message = "Dear ".$AcceptOrder->receivers_name.", Your order has been accepted. Please show this code to the deliveryman ".$AcceptOrder->verification_code." when you recieve the product.Thank you";

        $url = "http://sms.greenweb.com.bd/api.php";

        $data= array(
        'to'=>"$to",
        'message'=>"$message",
        'token'=>"$token"
        ); // Add parameters in key value
        $ch = curl_init(); // Initialize cURL
        curl_setopt($ch, CURLOPT_URL,$url);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $smsresult = curl_exec($ch);
        return response()->json(['message'=>'Order Accepted']);
      }
      else {
        return response()->json(['message'=>'You are not authorized to accept delivery']);
      }
    }

    public function OrderOngoing($id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      $Order->delivery_status = 2;
      $Order->save();

      return response()->json(['message'=>'Delivery ID number '.$id.' has Started']);
    }

    public function OrderDelivered(Request $request,$id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      //if (strtoupper($request->verification_code)==$Order->verification_code) {

        $Order->delivery_status = 3;
        if ($request->has('longitude')) {
          $Order->drop_off_lon = $request->longitude;
        }
        if ($request->has('latitude')) {
          $Order->drop_off_lat = $request->latitude;
        }
        $Order->save();
        return response()->json(['message'=>'Delivery ID number '.$id.' has been completed']);
    //  }else {
      //  return response()->json(['message'=>'Verification code did not match']);
      //}



    }
    public function OrderReturned($id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      $Order->delivery_status = 5;
      $Order->save();

      return response()->json(['message'=>'Delivery ID number '.$id.' has been Returned']);
    }
    //Booked Orders
    public function DeliveryMansOrders(Request $request)
    {
      $id = $request->user()->id;
      $UserOrders = DeliveryKoi::where('delivery_mans_id', $id)->where('delivery_status',1)->get();

      return $UserOrders->toJson();

    }
    public function OngoingOrderByDeliveryMan(Request $request)
    {
      $id = $request->user()->id;
      $orders = DeliveryKoi::where('delivery_mans_id',$id)->where('delivery_status',2)->get();

      return $orders->toJson();
    }
    public function CancelledOrderByDeliveryMan(Request $request)
    {
      $id = $request->user()->id;
      $orders = DeliveryKoi::where('delivery_mans_id',$id)->where('delivery_status',4)->get();

      return $orders->toJson();
    }


    // Available all orders
    public function AvailableOrders(Request $request)
    {
      $today = \Carbon\Carbon::today();
      $id = $request->user()->id;
      //$Company = DeliveryMan::where('delivery_man_id',$id)->first();
    //  $CompanyId = $Company->company_id;


        $orders = DeliveryKoi::where('delivery_status',0)->get();
        //->whereDate('created_at', $today)
        //;


      return $orders->toJson();

    }


    // Finisished Deliveries for a DeliveryMan
    public function AllDeliveredOrders(Request $request)
    {
      $id = $request->user()->id;
      $orders = DeliveryKoi::where('delivery_mans_id',$id)->where('delivery_status',3)->get();

      return $orders->toJson();
    }

    // Returned order by DeliveryMan
    public function AllReturnedOrders(Request $request)
    {
      $id = $request->user()->id;
      $orders = DeliveryKoi::where('delivery_mans_id',$id)->where('delivery_status',5)->get();

      return $orders->toJson();
    }


   public function notification(Request $request)
    {
      $user = User::findOrFail($request->id);
      $deviceID = $request->user()->device_ID;
      $response = OneSignal::postNotification([
        //  "included_segments"     => array('All'),
          "include_player_ids"    => array($user->device_ID),
          "contents"              => ["en" => $request->message],
          "android_group" =>'true'

      ]);
      return response()->json(['message' => 'Notification Sent']);
    }

    public function deliveryPrice()
    {
      return response()->json(['message'=>'60']);
    }


  /*  public function notification(Request $request)
    {
          $message = $request->message;
          $content = array(
        "en" => $message
        );

      $fields = array(
        'app_id' => "74881da6-0051-4a63-a008-39bf018375e5",
        //'include_player_ids' => array("c47e4b41-11d6-4d36-91b7-8d49e170e154"),
        'included_segments' => array('All'),
        'data' => array("foo" => "bar"),
        'contents' => $content,
        'android_group' => 'true'
      );

      $fields = json_encode($fields);
      print("\nJSON sent:\n");
      print($fields);

      $ch = curl_init();
      curl_setopt($ch, CURLOPT_URL, "https://onesignal.com/api/v1/notifications");
      curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json; charset=utf-8',
                             'Authorization: Basic ZjQxNGNjMTktOWUzOC00NDY0LWFkODMtYzU0Yjg0YTY0YjVj'));
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
      curl_setopt($ch, CURLOPT_HEADER, FALSE);
      curl_setopt($ch, CURLOPT_POST, TRUE);
      curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

      $response = curl_exec($ch);
      curl_close($ch);

      return $response;
      $response = sendMessage();
      $return["allresponses"] = $response;
      $return = json_encode( $return);
      return response()->json($return);
}
*/
      public function GetDeliveryCompany()
      {
        $User =  User::where('userType',4)->get(['id','name']);
        return $User->toJson();
      }


      public function DeliveryLocation(Request $request)
      {

        $locationUpdate = DeliveryMan::where('delivery_man_id',$request->user()->id)->first();
        if ($request->last_lon) {
          $locationUpdate->active = 1;
        }
        $locationUpdate->last_lon = $request->last_lon;
        $locationUpdate->last_lat = $request->last_lat;
        $locationUpdate->save();

        return response()->json(['message' => 'location updated']);

      }

      public function getLocationByCompany(Request $request)
      {
        //$gps = DeliveryMan::where('company_id',$request->user()->id)->get();
        $gps =  DB::table('DeliveryMan')->where('company_id',$request->user()->id)
        ->join('users','DeliveryMan.delivery_man_id','=','users.id')
        ->select('users.name','DeliveryMan.last_lon','DeliveryMan.last_lat')
        ->get();

        return $gps->toJson();
      }
      public function getLocationForAdmin(Request $request)
      {
        //$gps = DeliveryMan::where('company_id',$request->user()->id)->get();
        $gps =  DB::table('DeliveryMan')
        ->join('users','DeliveryMan.delivery_man_id','=','users.id')
        ->select('users.name','DeliveryMan.last_lon','DeliveryMan.last_lat','DeliveryMan.company_id')
        ->get();

        return $gps->toJson();
      }


      public function testsms($name,$number)
      {
        $to = $number;
        $token = "7211aa139c9eaaa7184cead6c1bc7bee";
        $message = "Dear ".$name." We have recieved your order. Thank you";

        $url = "http://sms.greenweb.com.bd/api.php";


        $data= array(
        'to'=>"$to",
        'message'=>"$message",
        'token'=>"$token"
        ); // Add parameters in key value
        $ch = curl_init(); // Initialize cURL
        curl_setopt($ch, CURLOPT_URL,$url);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $smsresult = curl_exec($ch);

        return response()->json($smsresult);
      }

      public function OwnSms($name,$number,$verification,$sender)
      {
        $client = new Client();

        $r = $client->request('POST', 'http://smsgateway.me/api/v3/messages/send', [
          'form_params' =>[
          'email' => 'tayef56@yahoo.com',
          'password' => 'r58num1sarker',
          'device' => '55290',
          'number' => $number,
          'message' => 'Dear '.$name.' your product will be delivered to you by tomorrow. Please show the this code to the delivery agent '.$verification.'. Thank you'.$sender.'',
        ]

        ]);
      }

      // ========================== ANALYTICS ===============================================

    /*  public function GetBusinessCount(Request $request)
      {
        $count = DeliveryKois::where('');
      }
      */

}
