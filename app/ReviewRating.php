<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class ReviewRating extends Model
{
    //
    protected $table='review_ratings';
    protected $fillable = [
        'pid',
        'user_id',
	    'review',
        'rating',
        'isAllowedToShow',
    ];

    public function reviewForPlace(){
    	return $this->belongsTo('App\Place');
    }
    //'user_id' the f_key in ReviewRating Table to User Table  
    public function reviewByUser(){
    	return $this->belongsTo('App\User','user_id');
    }
}
