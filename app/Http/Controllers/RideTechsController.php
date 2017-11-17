<?php namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\RideTechsRequestRides;
use App\RideTechs;
use App\RideTechsOfferRides;
class RideTechsController extends Controller {

    public function RideAnalytics()
    {
      $show = RideTechsRequestRides::all();
      $count = count($show);

      return response()->json(['Total Requested Ride' => $count]);
    }
    public function RequestRide(Request $request)
    {
      $create = RideTechsRequestRides::create($request->all()+['name'=> $request->user()->name,'contact_number'=>$request->user()->phone,'user_id'=> $request->user()->id]);

      return response()->json(['message' => 'Ride Request Complete. Someone from ride will call you soon. Thank you!']);
    }

    public function ShowRequestedRides()
    {
      $show = RideTechsRequestRides::all();

      return $show->toJson();
    }

    public function ShowRequestedRidesByUser($id)
    {
      $show = RideTechsRequestRides::where('user_id',$id)->get();

      return $show->toJson();
    }

    public function DeleteRideRequest($id)
    {
      $show = RideTechsRequestRides::findOrFail($id);
      $show->delete();
      return response()->json(['message' => 'Ride Request Deleted.']);

    }

    public function OfferRide(Request $request)
    {
      $create = RideTechsOfferRides::create($request->all()+['name'=> $request->user()->name,'number'=>$request->user()->phone,'user_id'=> $request->user()->id]);

      return response()->json(['message' => 'Ride Offering Complete. Someone from Ride will call you soon and talk about pricing. Thank you!']);
    }

    public function ShowOfferedRides()
    {
      $show = RideTechsOfferRides::all();

      return $show->toJson();
    }

}
