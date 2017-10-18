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
      $order = DeliveryKoi::create($request->all()+['user_id'=> $request->user()->id,'sender_name'=> $request->user()->name,'sender_number'=>$request->user()->phone]);

      return response()->json("Order Created");
    }

    public function OrderByID($id)
    {
      $OrderNumber = DeliveryKoi::findOrFail($id);

      return $OrderNumber->toJson();
    }
    
    public function updateOrder(Request $request, $id)
    {
      $updateOrder = DeliveryKoi::findOrFail($id);
      $updateOrder->pick_up = $request->pick_up;
      $updateOrder->drop_off = $request->drop_off;
      $updateOrder->drop_off_lon = $request->drop_off_lon;
      $updateOrder->drop_off_lat = $request->drop_off_lat;
      $updateOrder->pick_up_date = $request->pick_up_date;
      $updateOrder->preffered_time = $request->preffered_time;
      $updateOrder->product = $request->product;
      $updateOrder->product_weight = $request->product_weight;
      $updateOrder->product_price = $request->product_price;
      $updateOrder->receivers_name = $request->receivers_name;
      $updateOrder->receivers_number = $request->receivers_number;
      $updateOrder->save();

      return response()->json("Order updated");
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
      $Order->delivery_status = 2;
      $Order->save();

      return response()->json("Delivery ID number ".$id." has been Cancelled");
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
      return response()->json("Order Deleted");;
    }


    //=================== Delivery Man Part ==================
    public function AcceptOrder(Request $request, $id)
    {
       $AcceptOrder = DeliveryKoi::findOrFail($id);
       $AcceptOrder->delivery_mans_id = $request->user()->id;
       $AcceptOrder->delivery_man_name = $request->user()->name;
       $AcceptOrder->delivery_man_number = $request->user()->number;
       $AcceptOrder->save();
       return response()->json("Ride Accepeted");

    }
    public function OrderOngoing($id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      $Order->delivery_status = 0;
      $Order->save();

      return response()->json("Delivery ID number ".$id." has Started");
    }

    public function OrderDelivered($id)
    {
      $Order = DeliveryKoi::findOrFail($id);
      $Order->delivery_status = 1;
      $Order->save();

      return response()->json("Delivery ID number ".$id." has been completed");
    }
    //Booked Orders
    public function DeliveryMansOrders(Request $request)
    {
      $id = $request->user()->id;
      $UserOrders = DeliveryKoi::where('delivery_mans_id', $id)->get();

      return $UserOrders->toJson();

    }
    // Available all orders
    public function AvailableOrders()
    {
      $today = \Carbon\Carbon::today();
      $orders = DeliveryKoi::whereNull('delivery_mans_id')->whereDate('created_at', $today)->get();
      return $orders->toJson();

    }
    // Finisished Deliveries for a DeliveryMan
    public function AllDeliveredOrders(Request $request)
    {
      $id = $request->user()->id;
      $orders = DeliveryKoi::where('delivery_mans_id',$id)->where('delivery_status',2)->get();

      return $orders->toJson();
    }






}
