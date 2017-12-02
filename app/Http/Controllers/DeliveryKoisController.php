<?php namespace App\Http\Controllers;


use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\DeliveryKoi;
use App\DeliveryMan;
use App\User;
use OneSignal;
class DeliveryKoisController extends Controller {

  //  const MODEL = "App\DeliveryKoi";

    //use RESTActions;
    //======================== Customer/User Part ===============
    public function PlaceOrder(Request $request)
    {
      $order = DeliveryKoi::create($request->all()+['user_id'=> $request->user()->id,'sender_name'=> $request->user()->name,'sender_number'=>$request->user()->phone,'delivery_fee'=> ($request->product_weight*25)+75]);

      $message = ' '.$request->user()->name.'  Requested a Delivery';
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

    public function UserOrders(Request $request)
    {
      $id = $request->user()->id;
      $UserOrders = DeliveryKoi::where('user_id', $id)->get();

      return  $UserOrders->toJson();
    }

    public function OrderCancelled($id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      $Order->delivery_status = 4;
      $Order->save();



      return response()->json(['message'=>'Delivery ID number '.$id.' has been Cancelled']);
    }



    //================== Admin Part============================

    public function getAllOrder()
    {
      $AllOrder = DeliveryKoi::all();

      return $AllOrder->toJson();
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
    public function getDeliveryMan()
    {
      $user = User::where('userType',5)->get();
      return $user->toJson();
    }



    //=================== Delivery Man Part ==================
    public function AcceptOrder(Request $request, $id)
    {
       $AcceptOrder = DeliveryKoi::findOrFail($id);
       $AcceptOrder->delivery_mans_id = $request->user()->id;
       $AcceptOrder->delivery_man_name = $request->user()->name;
       $AcceptOrder->delivery_man_number = $request->user()->number;
       $AcceptOrder->delivery_status = 1;
       $AcceptOrder->save();
       return response()->json(['message'=>'Order Accepted']);

    }
    public function OrderOngoing($id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      $Order->delivery_status = 2;
      $Order->save();

      return response()->json(['message'=>'Delivery ID number '.$id.' has Started']);
    }

    public function OrderDelivered($id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      $Order->delivery_status = 3;
      $Order->save();

      return response()->json(['message'=>'Delivery ID number '.$id.' has been completed']);
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
    public function AvailableOrders()
    {
      $today = \Carbon\Carbon::today();
      $orders = DeliveryKoi::whereNull('delivery_mans_id')->where('delivery_status',0)
      //->whereDate('created_at', $today)
      ->get();
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
      return response()->json(['message'=>'100']);
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
        $locationUpdate->last_lon = $request->last_lon;
        $locationUpdate->last_lat = $request->last_lat;
        $locationUpdate->save();

        return response()->json(['message' => 'location updated']);

      }

      public function getLocationByCompany(Request $request)
      {
        $gps = DeliveryMan::where('company_id',641)->get();
        return $gps->toJson();
      }

}
