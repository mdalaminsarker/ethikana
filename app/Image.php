<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Image extends Model
{
    //
    protected $table = "images";
    protected $fillable =[
      'pid',
      'user_id',
      'imageGetHash',
      'imageTitle',
      'imageRemoveHash',
      'imageLink',
      'isShowable',
      'relatedTo'
    ];

    public function places()
    {
        return $this->belongsTo('App\Place','id');
    }
}
