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
        $q = Input::get('query');
        //$q=$request->query;
        //NATURAL LANGUAGE MODE
        //BOOLEAN MODE
        $posts = Place::whereRaw(
            "MATCH(Address,city,area,uCode) AGAINST(? IN BOOLEAN MODE)", 
            array($q)
        )->get();

        //return View::make('posts.index', compact('posts'));
        //$results = $query->get();

        return $posts;
    }
    public function indexCode(Request $request){
        $q = Input::get('query');
        //$q=$request->query;
        //NATURAL LANGUAGE MODE
        //BOOLEAN MODE
        $posts = Place::whereRaw(
            "MATCH(Address,city,area,uCode) AGAINST(? IN NATURAL LANGUAGE MODE)", 
            array($q)
        )->get();

        //return View::make('posts.index', compact('posts'));
        //$results = $query->get();

        return $posts;
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
