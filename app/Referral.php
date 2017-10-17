<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Referral extends Model
{
    //
    protected $table = "referrals_log";
    protected $fillable =[
      'ref_code_referrer',
      'ref_code_redeemer',
    ];
}
