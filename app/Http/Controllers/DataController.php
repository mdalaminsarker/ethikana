<?php namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use DB;
use App\Place;
class DataController extends Controller {

  /*
  @@ area wise divide search
  */
    public function getArea()
    {
      $area = DB::select("SELECT id, name FROM Area order by name ASC");
      return response()->json(['area' => $area]);
    }
    public function getAreaByPolygon()
    {
      $area = DB::select("SELECT  id, name,  ST_AsGeoJSON(area) FROM Area order by name ASC");
      return response()->json(['area' => $area]);
    }
    // Insert polygon
    public function insertArea(Request $request)
    {
      $insert = DB::select("INSERT INTO Area (area, name) VALUES (GEOMFROMTEXT('POLYGON(($request->area))'),'$request->name')");

      return response()->json(['Message' => 'Inserted'],200);
    }
    public function updateArea(Request $request,$id)
    {
      $insert = DB::select("UPDATE Area SET area = GEOMFROMTEXT('POLYGON(($request->area))') WHERE id = '$id'");
      return response()->json(['Message' => 'Polygon updated'],200);
    }

    public function getAreaDataPolygonWise(Request $request)
    {
      if ($request->has('subType')) {
        $subtype = $request->subType;
      }else {
        $subtype = 'bkash';
      }
      if ($request->has('area')) {
        $area = $request->area;
      }
      else {
        $area = 'Baridhara DOHS';
      }
      if ($subtype=='all') {
        $places = DB::select("SELECT id, Address, subType, pType, longitude,latitude, uCode,astext(location) FROM places_2 WHERE st_within(location,(select area from Area where name='$area') )");
      }
      else {
        $places = DB::select("SELECT id, Address, subType, pType, longitude,latitude, uCode,astext(location) FROM places_2 WHERE st_within(location,(select area from Area where name='$area') ) and subType LIKE '%$subtype%'");


      }
          return response()->json([
              'Total' => count($places),
              'places'=> $places
            ]);

    }
    // search data by polygon
    public function SearchInPolygon(Request $request)
    {
      if ($request->has('address')) {
        $address = $request->address;
      }else {
        $address = 'barikoi';
      }
      if ($request->has('area')) {
        $area = $request->area;
      }
      else {
        $area = 'Mirpur Section 2';
      }

      $places = DB::select("SELECT id, Address, subType, pType, longitude,latitude, astext(location) FROM places_2 WHERE st_within(location,(select area from Area where name='$area') ) and Address LIKE '%$address%' LIMIT 5");

        return response()->json([
            'Total' => count($places),
            'places'=> $places
          ]);


    }


  /*
    @@ fix data spelling mistake
  */
      public function UpdateWordZone(Request $request)
      {
        $place = Place::where($request->param, 'LIKE', '%'.$request->data.'%')->update([$request->updateField => $request->ward]);

        return response()->json('Updated');
      }
      public function replace(Request $request)
      {
        DB::table('places')->update(['Address' => DB::raw("REPLACE(Address, '".$request->x."', '".$request->y."')")]);

        return response()->json('ok');
      }

      public function dataFix()
      {
        DB::select("SELECT Address, area, REPLACE(Address, 'Road 103', 'Bir Uttam Shamsul Alam Avenue') from places WHERE Address LIKE '%Road 103%' AND area = 'Kakrail'");
      }

      /*
      Transfer data to new column

      */

      public function MergeColumn(Request $request)
      {
        $table = $request->table;
        $index = $request->index;
        $field = $request->field;
        //DB::select("UPDATE places_copy SET location =  GeomFromText(CONCAT('POINT(',longitude, ' ', latitude,')'))");
        //DB::select("UPDATE places_3 SET new_address = CONCAT(Address,", ", area)")
        DB::select("ALTER TABLE places_copy MODIFY location GEOMETRY NOT NULL");
        DB::select("ALTER TABLE '$table' ADD '$index' INDEX('$field') ");
      }

}
