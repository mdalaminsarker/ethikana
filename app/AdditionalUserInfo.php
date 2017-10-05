<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class AdditionalUserInfo extends Model
{
    //
    protected $table = 'additional_user_infos';
    protected $fillable = [
	    'user_id',
	    'user_gender',
	    'user_occupation',
	    'user_nid',
	    'user_dob'
	];
    public function userInfoMore(){
    	$this->belongsTo('App\User');
    }

}
