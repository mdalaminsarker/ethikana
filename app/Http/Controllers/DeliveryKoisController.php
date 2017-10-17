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
      $order =DeliveryKoi::create($request->all());

      return response()->json("Order Created");
    }

    public function OrderByID($id)
    {
      $OrderNumber = DeliveryKoi::findOrFail($id);

      return $OrderNumber->toJson();
    }
    public function updateOrder($id)
    {
      return response()->json("Order updated");
    }



    //================== Admin Part================

    public function getAllOrder()
    {
      $AllOrder = DeliveryKoi::all();

      return $AllOrder->toJson();
    }



    //=================== Delivery Man Part ==================
    public function AcceptOrder(Request $request, $id)
    {
      
    }

}
