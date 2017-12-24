<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use DB;
use Auth;
use App\User;
use App\Place;
use App\SavedPlace;
use App\Referral;
use App\analytics;
use App\Image;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\Storage;
use League\Flysystem\Filesystem;
use League\Flysystem\Adapter\Local;
use Carbon\Carbon;

class SearchController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function indexA(Request $request)
    {
        //
        // $searchTerms = explode(' ', $searchTerms);
        // $query = Place::query();

        // foreach($searchTerms as $searchTerm)
        // {
        //     $query->where(function($q) use ($searchTerm){
        //         $q->where('Address', 'like', '%'.$searchTerm.'%')
        //         ->orWhere('uCode', 'like', '%'.$searchTerm.'%');
        //         // and so on
        //     });
        // }

        // $result = Place::where('uCode', '=', $name)
        //     ->orWhere(function($query) use ($name)
        //     {
        //         $query->where('Address','like','%'.$name.'%')
        //               ->where('flag', '=', 1);
        //     })
        //     ->get();
        //https://hooks.slack.com/services/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
        //https://hooks.slack.com/services/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
        //   define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');


        // // Make your message
        //   $message = array('payload' => json_encode(array('text' => "searched for: '".$searchTerms. "' from App")));
        // // Use curl to send your message
        //   $c = curl_init(SLACK_WEBHOOK);
        //   curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
        //   curl_setopt($c, CURLOPT_POST, true);
        //   curl_setopt($c, CURLOPT_POSTFIELDS, $message);
        //   curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
        //   $res = curl_exec($c);
        //   curl_close($c);


    }
    public function index(Request $request){
       $terms=Input::get('query');
       $q = Input::get('query');
       //$srch=$request->query;
       //$q=$request->query;
       //NATURAL LANGUAGE MODE
       //BOOLEAN MODE
       if(Place::where('uCode','=',$terms)->exists()){
         $posts=Place::with('images')->where('uCode','=',$terms)->get();
       }
       else{
         $area = DB::table('places')
           ->where('area', 'LIKE', '%'.$q.'%');
         $posts = Place::with('images')->where('flag','=',1)
         ->where('address', 'SOUNDS LIKE', '%'.$q.'%')
         ->limit(20)
         ->get(['id','longitude','latitude','Address','area','city','postCode','uCode','pType','subType']);
         /*$posts = Place::with('images')->where('flag','=',1)
         ->where("MATCH(Address,area) AGAINST ('.*$q*.' IN BOOLEAN MODE)")
         ->limit(20)
         ->get();*/
        if (count($posts)==0) {
          $posts = $this->searchx($q);
        }
          /* $posts=DB::select("SELECT id,longitude,latitude,Address,area,city,postCode,uCode, pType, subType FROM
                     places
                     WHERE
                     MATCH (Address, area)
                     AGAINST ('.$request->search*' IN BOOLEAN MODE)
                     LIMIT 10");
         }else {
           $posts = 'Did not get anything like that ';
         }*/

       }



       DB::table('analytics')->increment('search_count',1);
       //https://hooks.slack.com/services/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
       //https://hooks.slack.com/services/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
       define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
  /*   if (isset($_SERVER['HTTP_CLIENT_IP']))
         $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
     else if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
         $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
     else if(isset($_SERVER['HTTP_X_FORWARDED']))
         $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
     else if(isset($_SERVER['HTTP_FORWARDED_FOR']))
         $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
     else if(isset($_SERVER['HTTP_FORWARDED']))
         $ipaddress = $_SERVER['HTTP_FORWARDED'];
     else if(isset($_SERVER['REMOTE_ADDR']))
         $ipaddress = $_SERVER['REMOTE_ADDR'];
     else
         $ipaddress = 'UNKNOWN';
     $clientDevice = gethostbyaddr($ipaddress);*/
    $clientDevice = 'x';
   // Make your message

   $message = array('payload' => json_encode(array('text' => "Someone searched for: '".$terms. "' , ip:".$clientDevice)));


   // Use curl to send your message
     $c = curl_init(SLACK_WEBHOOK);
     curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
     curl_setopt($c, CURLOPT_POST, true);
     curl_setopt($c, CURLOPT_POSTFIELDS, $message);
     curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
     $res = curl_exec($c);
     curl_close($c);

  /*   $file=Storage::disk('search')->get('search_log.json');
     $data = json_decode($file,true);
     unset($file);
     //you need to add new data as next index of data.
     $data[] =array(
         'dateTime'=> date('Y-m-d H:i:s'),
         'terms' => $terms,
         'url' => $request->url(),
         'from_IP' =>$clientDevice
         );
     $result1=json_encode($data,JSON_PRETTY_PRINT);
     //file_put_contents('search_log.json', $result);
     Storage::disk('search')->put('search_log.json', $result1);
     unset($result1);
     $log_save="ok";
*/
     return $posts;
   }

  public function searchx($search)
    {
      //$result = Place::where('area','like',$name)->first();
      $result = DB::select("SELECT id,longitude,latitude,Address,area,city,postCode,uCode,pType,subType FROM
                places
                WHERE
                MATCH (Address, area)
                AGAINST ('+$search*' IN BOOLEAN MODE) AND flag = 1
                LIMIT 10");

      return response()->json(['places' =>$result]);
    }

    public function findNearby(Request $request){
        $terms=Input::get('query');
        if($request->has('longitude'))
        {
          $lon=Input::get('longitude');
        }
        if($request->has('latitude')){
          $lat=Input::get('latitude');
        }

        $q = Input::get('query');
        //$srch=$request->query;
        //$q=$request->query;
        //NATURAL LANGUAGE MODE
        //BOOLEAN MODE
       // Place::where('uCode','like','%'.$terms.'%')->exists()
        if(Place::where('uCode','=',$terms)->exists())
        {
          $posts=Place::with('images')->where('uCode','=',$terms)->get();
        }
        else{
          $posts = Place::with(array('images' => function($query)
          {
            $query->select('pid','imageLink');}))->where('flag','=',1)
                  ->whereRaw("MATCH(Address,uCode,pType,subType) AGAINST(? IN BOOLEAN MODE)",array($q))
                  ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
                  ->having('distance','<=',2)
                  ->orderBy('distance')
                  ->limit(2)
                  ->get();
          }


          if(count($posts)==0){
            $ar[]=array("text"=>"my apologies,Could not find '".$terms."'");
              return new JsonResponse([
                  'messages'=>$ar
              ]);
          }
          else{
            foreach ($posts as $post) {
              $ad=$post->Address;
              $sub=$post->area.','.$post->city;
              $code=$post->uCode;
              $weblink="https://barikoi.com/#/code/".$code;

              //echo count($post->images);

              if(count($post->images)==0){
                $img='';
                // $posts1[]=array('title'=>$ad,'image_url'=>NULL,'subtitle'=>$sub,'buttons'=>array([
                //     'type'=>'web_url','url'=>$weblink,'title'=>$code]));
              }else{
                foreach ($post->images as $p) {
                  $img=$p->imageLink;}
              }
              $posts1[]=array('title'=>$ad,'image_url'=>$img,'subtitle'=>$sub,'buttons'=>array([
                    'type'=>'web_url','url'=>$weblink,'title'=>$code]));
             }

              $messages[]=array('attachment'=>[
                        'type'=>'template','payload'=>
                                [
                                    'template_type'=>'generic',
                                    'elements' =>$posts1
                                ]
                            ]
                        );
        // $ar[]=array("text"=>"Searched for:".$terms." Lon:".$longitude." Lat:".$latitude);
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
      $message = array('payload' => json_encode(array('text' => "Someone searched nearby for: '".$terms. "' ,from BOT")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);
             return new JsonResponse([
                  'messages'=>$messages,
              ]);
        }
    }
    //this function is used by the bot to search all
      public function findAll(Request $request){
        $terms=Input::get('query');

        $q = Input::get('query');
        //$srch=$request->query;
        //$q=$request->query;
        //NATURAL LANGUAGE MODE
        //BOOLEAN MODE
       // Place::where('uCode','like','%'.$terms.'%')->exists()
        if(Place::where('uCode','=',$terms)->exists())
        {
          $posts=Place::with('images')->where('uCode','=',$terms)->get();
        }
        else{
          $posts = Place::with(array('images' => function($query)
          {
            $query->select('pid','imageLink');}))->where('flag','=',1)
                  ->whereRaw("MATCH(Address,uCode,pType,subType) AGAINST(? IN BOOLEAN MODE)",array($q))
                  ->limit(4)
                  ->get();
          }


          if(count($posts)==0){
            $ar[]=array("text"=>"my apologies,could not find anything related to' ".$terms." ' nearby");
              return new JsonResponse([
                  'messages'=>$ar
              ]);
          }
          else{
            foreach ($posts as $post) {
              $ad=$post->Address;
              $sub=$post->area.','.$post->city;
              $code=$post->uCode;
              $weblink="https://barikoi.com/#/code/".$code;

              //echo count($post->images);

              if(count($post->images)==0){
                $img='';
                // $posts1[]=array('title'=>$ad,'image_url'=>NULL,'subtitle'=>$sub,'buttons'=>array([
                //     'type'=>'web_url','url'=>$weblink,'title'=>$code]));
              }else{
                foreach ($post->images as $p) {
                  $img=$p->imageLink;}
              }
              $posts1[]=array('title'=>$ad,'image_url'=>$img,'subtitle'=>$sub,'buttons'=>array([
                    'type'=>'web_url','url'=>$weblink,'title'=>$code]));
             }

              $messages[]=array('attachment'=>[
                        'type'=>'template','payload'=>
                                [
                                    'template_type'=>'generic',
                                    'elements' =>$posts1
                                ]
                            ]
                        );
        // $ar[]=array("text"=>"Searched for:".$terms." Lon:".$longitude." Lat:".$latitude);
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
        $message = array('payload' => json_encode(array('text' => "Someone searched for: '".$terms. "' ,from BOT")));
        // Use curl to send your message
          $c = curl_init(SLACK_WEBHOOK);
          curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
          curl_setopt($c, CURLOPT_POST, true);
          curl_setopt($c, CURLOPT_POSTFIELDS, $message);
          curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
          $res = curl_exec($c);
          curl_close($c);
                 return new JsonResponse([
                      'messages'=>$messages,
                  ]);
        }
      }

    public function indexCode(Request $request){
        $q = Input::get('query');
        //$q=$request->query;
        //NATURAL LANGUAGE MODE
        //BOOLEAN MODE
        $posts = Place::whereRaw(
            "MATCH(Address,uCode) AGAINST(? IN NATURAL LANGUAGE MODE)",
            array($q)
        )->get();

        //return View::make('posts.index', compact('posts'));
        //$results = $query->get();
            //Save the log to a .json file

        $file = file_get_contents('search_log.json', true);
        $data = json_decode($file,true);
        unset($file);

        //you need to add new data as next index of data.
        $data[] =array(
            'dateTime'=> date('Y-m-d H:i:s'),
            'terms' => $terms,
            'url' => $request->url(),
            'from_IP' =>$clientDevice
            );
        $result=json_encode($data,JSON_PRETTY_PRINT);
        file_put_contents('search_log.json', $result);
        unset($result);
        $log_save="ok";

        return $posts;
    }


    //Food
    public function food(Request $request){
      $terms=Input::get('query');
      if($request->has('longitude'))
      {
        $lon=Input::get('longitude');
      }
      if($request->has('latitude')){
        $lat=Input::get('latitude');
      }

      if($request->has('within')){
        $distance=Input::get('within');
      }else{
        $distance=10;
      }


      $q = 'Food';
      //$srch=$request->query;
      //$q=$request->query;
      //NATURAL LANGUAGE MODE
      //BOOLEAN MODE
     // Place::where('uCode','like','%'.$terms.'%')->exists()
      if(Place::where('uCode','=',$terms)->exists())
      {
        $posts=Place::with('images')->where('uCode','=',$terms)->get();
      }
      else{
        $posts = Place::with(array('images' => function($query)
        {
          $query->select('pid','imageLink');}))->where('flag','=',1)->where('pType','=','Food')
                // ->whereRaw("MATCH(Address,uCode,pType,subType) AGAINST(? IN BOOLEAN MODE)",array($q))
                ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
                ->having('distance','<=',$distance)
                ->orderBy('distance')
                ->limit(5)
                ->get();
        }
        //Reply to Bot
        if(count($posts)==0){
          $ar[]=array("text"=>"My apologies,could not find anything related to your search.");
            return new JsonResponse([
                'messages'=>$ar
            ]);
        }
        else{
          foreach ($posts as $post) {
            $ad=$post->Address;
            $sub=$post->area.','.$post->city;
            $code=$post->uCode;
            $weblink="https://barikoi.com/#/code/".$code;
            //echo count($post->images);
            if(count($post->images)==0){
              $img='';
              // $posts1[]=array('title'=>$ad,'image_url'=>NULL,'subtitle'=>$sub,'buttons'=>array([
              //     'type'=>'web_url','url'=>$weblink,'title'=>$code]));
            }else{
              foreach ($post->images as $p) {
                $img=$p->imageLink;}
            }
            $posts1[]=array('title'=>$ad,'image_url'=>$img,'subtitle'=>$sub,'buttons'=>array([
                  'type'=>'web_url','url'=>$weblink,'title'=>$code]));
           }

            $messages[]=array('attachment'=>[
                      'type'=>'template','payload'=>
                              [
                                  'template_type'=>'generic',
                                  'elements' =>$posts1
                              ]
                          ]
                      );
      // $ar[]=array("text"=>"Searched for:".$terms." Lon:".$longitude." Lat:".$latitude);
            define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
                  $message = array('payload' => json_encode(array('text' => "Someone searched nearby for: '".$q. "' ,from BOT")));
          // Use curl to send your message
            $c = curl_init(SLACK_WEBHOOK);
            curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($c, CURLOPT_POST, true);
            curl_setopt($c, CURLOPT_POSTFIELDS, $message);
            curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
            $res = curl_exec($c);
            curl_close($c);
         return new JsonResponse([
              'messages'=>$messages,
          ]);
        }
    }
    //Travel
    public function travel(Request $request){
      $terms=Input::get('query');
      if($request->has('longitude'))
      {
        $lon=Input::get('longitude');
      }
      if($request->has('latitude')){
        $lat=Input::get('latitude');
      }

      if($request->has('within')){
        $distance=Input::get('within');
      }else{
        $distance=10;
      }


      $q = 'Tourist Spot';
      //$srch=$request->query;
      //$q=$request->query;
      //NATURAL LANGUAGE MODE
      //BOOLEAN MODE
     // Place::where('uCode','like','%'.$terms.'%')->exists()
      if(Place::where('uCode','=',$terms)->exists())
      {
        $posts=Place::with('images')->where('uCode','=',$terms)->get();
      }
      else{
        $posts = Place::with(array('images' => function($query)
        {
          $query->select('pid','imageLink');}))->where('flag','=',1)->where('pType','=','Tourism')
                // ->whereRaw("MATCH(Address,uCode,pType,subType) AGAINST(? IN BOOLEAN MODE)",array($q))
                ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
                ->having('distance','<=',$distance)
                ->orderBy('distance')
                ->limit(5)
                ->get();
        }
        //Reply to Bot
        if(count($posts)==0){
          $ar[]=array("text"=>"My apologies,could not find anything related to your search.");
            return new JsonResponse([
                'messages'=>$ar
            ]);
        }
        else{
          foreach ($posts as $post) {
            $ad=$post->Address;
            $sub=$post->area.','.$post->city;
            $code=$post->uCode;
            $weblink="https://barikoi.com/#/code/".$code;
            //echo count($post->images);
            if(count($post->images)==0){
              $img='';
              // $posts1[]=array('title'=>$ad,'image_url'=>NULL,'subtitle'=>$sub,'buttons'=>array([
              //     'type'=>'web_url','url'=>$weblink,'title'=>$code]));
            }else{
              foreach ($post->images as $p) {
                $img=$p->imageLink;}
            }
            $posts1[]=array('title'=>$ad,'image_url'=>$img,'subtitle'=>$sub,'buttons'=>array([
                  'type'=>'web_url','url'=>$weblink,'title'=>$code]));
           }

            $messages[]=array('attachment'=>[
                      'type'=>'template','payload'=>
                              [
                                  'template_type'=>'generic',
                                  'elements' =>$posts1
                              ]
                          ]
                      );
      // $ar[]=array("text"=>"Searched for:".$terms." Lon:".$longitude." Lat:".$latitude);
           define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
                  $message = array('payload' => json_encode(array('text' => "Someone searched nearby for: '".$q. "' ,from BOT")));
          // Use curl to send your message
            $c = curl_init(SLACK_WEBHOOK);
            curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($c, CURLOPT_POST, true);
            curl_setopt($c, CURLOPT_POSTFIELDS, $message);
            curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
            $res = curl_exec($c);
            curl_close($c);

          //  $var ="Someone searched nearby for: '".$q. "' ,from BOT";
            //$this->slack($var);
         return new JsonResponse([
              'messages'=>$messages,
          ]);
        }
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }
    public function searchLog(){
      //$file = file_get_contents('search_log.json', true);
      $file=Storage::disk('search')->get('search_log.json');
      $data = json_decode($file,true);
      //unset($file);
      //return $data;
      $d=array();
      $day=array();
      $word=array();
      foreach($data as $item) { //foreach element in $arr
        //$dateTime = new DateTime($item['dateTime']);
        $dateTime1=Carbon::parse($item['dateTime'])->format('d-m-Y');
        $dateTime=Carbon::parse($item['dateTime'])->format('F-Y');
        $searchTerms=$item['terms'];
        //$date = $item['dateTime']; //etc
        //print $date.'<br>';
        $d[]=$dateTime;
        $day[]=$dateTime1;
        $word[]=$searchTerms;
      }
      $search_terms = array_count_values($word);
      arsort($search_terms, SORT_NUMERIC);
      //return $d;
      //$p=array();
      $p[]=array_count_values($d);
      $q[]=array_count_values($day);
      //$words[]=array_count_values($word);
      //return $p;
      //$json_string = json_encode($p, JSON_PRETTY_PRINT);
      //$json_string1 = json_encode($q, JSON_PRETTY_PRINT);
      return new JsonResponse([
          "search_terms"=>$search_terms,
          "per_month_search"=>$p,
          "per_day_search" => $q
        ]);
      //you need to add new data as next index of data.
      // $data[] =array(
      //     'dateTime'=> date('Y-m-d H:i:s'),
      //     'terms' => $terms,
      //     'url' => $request->url(),
      //     'from_IP' =>$clientDevice
      //     );
      // $result=json_encode($data,JSON_PRETTY_PRINT);
      // file_put_contents('search_log.json', $result);
      // unset($result);
      // $log_save="ok";

      //return $date;
    }
    public function slack($var)
    {
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
            $message = array('payload' => json_encode(array('text' => $var)));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);
    }
}
