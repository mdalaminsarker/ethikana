<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Place;
use Illuminate\Http\JsonResponse;
class PlaceController extends Controller
{
    //

    public function generateRandomString($length = 10) {
      $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      $charactersLength = strlen($characters);
      $randomString = '';
      for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
      }
      return $randomString;
    }

    public function generateRandomNumber($length = 10) {
      $characters = '0123456789';
      $charactersLength = strlen($characters);
      $randomString = '';
      for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
      }
      return $randomString;
    }

    public function StorePlace(Request $request)
    {

      $string = $this->generateRandomString(4);
      $number = $this->generateRandomNumber(4);
      $ucode =  ''.$string.''.$number.'';
      $input = new Place;
      $input->longitude = $request->longitude;
      $input->latitude = $request->latitude;
      $input->Address = $request->Address;
      $input->uCode = $ucode;
      $input->save();

      return response()->json($ucode);
    }
    public function KhujTheSearch($code)
    {

      $place = Place::where('uCode','=',$code)->first();
      $lon = $place->longitude;
      $lat = $place->latitude;
      $Address = $place->Address;
      return response()->json([
        'lon' => $lon,
        'lat' => $lat,
        'address' => $Address
      ]);
    }
}
