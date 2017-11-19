<?php namespace App\Http\Controllers;


use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\DeliveryKoi;
class DeliveryKoisController extends Controller {

  //  const MODEL = "App\DeliveryKoi";

    //use RESTActions;
    //======================== Customer/User Part ===============
    public function PlaceOrder(Request $request)
    {
      $order = DeliveryKoi::create($request->all()+['user_id'=> $request->user()->id,'sender_name'=> $request->user()->name,'sender_number'=>$request->user()->phone,'delivery_fee'=> ($request->product_weight*20)+100]);

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


    public function DeleteOrder($id)
    {
      $UserOrders = DeliveryKoi::findOrFail($id);
      $UserOrders->delete();
      return response()->json(['message'=>'Order Deleted']);;
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






}