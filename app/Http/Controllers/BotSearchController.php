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
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Input;
use Carbon\Carbon;
use Sunra\PhpSimple\HtmlDomParser;

class BotSearchController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function test1(Request $request)
    {
        $query = urlencode(Input::get('searchquery'));
        $useragent = "Opera/9.80 (J2ME/MIDP; Opera Mini/4.2.14912/870; U; id) Presto/2.4.15";
        //$useragent="Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1"
        $ch = curl_init ("");
        $query=urlencode(Input::get('searchquery'));
       // curl_setopt ($ch, CURLOPT_URL, "http://www.google.com/search?hl=en&tbo=d&site=&source=hp&q=".$query);
        curl_setopt($ch, CURLOPT_URL, 'http://www.google.com/search?q='.$query.'');
        curl_setopt ($ch, CURLOPT_USERAGENT, $useragent); // set user agent
        curl_setopt ($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
        $str = curl_exec ($ch);
       // $nowwhat=json_decode($output ,true);
        curl_close($ch);
       // $html= str_get_html($str);
        echo $html = HtmlDomParser::str_get_html($str);

        // $curl = curl_init();  
        // curl_setopt($curl, CURLOPT_URL, 'http://www.google.com/search?q='.$query.'');   
        // curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);   
        // curl_setopt($curl, CURLOPT_FOLLOWLOCATION, TRUE);
        // //curl_setopt($curl, CURLOPT_USERAGENT,random_user_agent());
        // curl_setopt ($curl, CURLOPT_USERAGENT, $useragent);
        // $str = curl_exec($curl);   
        // curl_close($curl);   

        // $html= str_get_html($str);  
        $title=array();
        $result = array();
        $i = 0;
        // foreach($html->find('div[class=_NId') as $element) {
        //     foreach($element->find('h3[class=r]') as $item) 
        //     {
        //         $title[$i] = ''.$item->plaintext.'' ;
        //     }
        //        $i++;
        // }
        // foreach($html->find('li.g') as $g)
        // {
         
        //   $h3 = $g->find('h3.r', 0);
        //   $s = $g->find('div.s', 0);
        //   $a = $h3->find('a', 0);
        //   $result[] = array('title' => strip_tags($a->innertext), 
        //     'link' => $a->href, 
        //     'description' => strip_tags_content($s->innertext));
        // }
        // print_r($result);
        //echo $nowwhat;
        $linkObjs = $html->find('h3.r a');
        foreach ($linkObjs as $linkObj) {
            $title = trim($linkObj->plaintext);
            $link  = trim($linkObj->href);
            
            // if it is not a direct link but url reference found inside it, then extract
            if (!preg_match('/^https?/', $link) && preg_match('/q=(.+)&amp;sa=/U', $link, $matches) && preg_match('/^https?/', $matches[1])) {
                $link = $matches[1];
            } else if (!preg_match('/^https?/', $link)) { // skip if it is not a valid link
                continue;    
            }
            
            echo '<p>Title: ' . $title . '<br />';
            echo 'Link: ' . $link . '</p>';    
        }
    }
    public function index(Request $request){
        $terms=Input::get('query');
        $q = '+'.Input::get('query');
        //$srch=$request->query;
        //$q=$request->query;
        //NATURAL LANGUAGE MODE
        //BOOLEAN MODE
        //Place::where('uCode','like','%'.$terms.'%')->exists()
        if(Place::where('uCode','=',$terms)->exists()){
          $posts=Place::with('images')->where('uCode','=',$terms)->select('Address as title','imageLink as image_url','uCode as title')->get();
        }
        else{
          $posts = Place::with(array('images' => function($query)
          {$query->select('pid','imageLink');}))->where('flag','=',1)
                  ->whereRaw("MATCH(Address,uCode) AGAINST(? IN BOOLEAN MODE)",array($q))
                  ->get();
        } 
          $ad=$posts[0]->Address; 
        $posts1[]=array('title'=>$ad);

      $ucode="ADNN8393";
      $buttons[]=array("type"=>"web_url","url"=>"https://barikoi.com/#/code/".$ucode,"title"=>"Something");

      // $elements[]=array('title'=>'GP House',
      //       'image_url'=>'',
      //       'subtitle'=>'',
      //       'buttons'=>$buttons);
     // $elements[]=$posts;

      //IMPORTANT:
      // transform $posts into $buttons and $elements
      $messages[]=array('attachment'=>[
                        'type'=>'template','payload'=>
                                [
                                    'template_type'=>'generic',
                                    'elements' =>$posts
                                ]
                            ]
                        );
      //$log_save=true;
      //return $posts;
      // return new JsonResponse([
      //     'search_result'=>$posts,
      //     'array'=>$terms,
      //     'log_saved'=>$log_save
      //   ]);
       return new JsonResponse([
            'messages'=>$messages
        ]);
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
}
