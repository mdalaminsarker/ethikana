<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateApiTokenTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('tokens', function (Blueprint $table) {
            $table->increments('id'); // primary key:increments
            $table->integer('user_id')->unsigned(); //user_type: business
            $table->string('key')->unique(); // the api_key=base64(userId:RandomUniqueKey8/10Char)
            $table->tinyInteger('isActive')->unsigned()->default(1); // is the API-kEY active?
            $table->integer('get_count')->nullable(); //api GET route call count
            $table->integer('post_count')->nullable(); //api POST route call count
            $table->integer('call_caps')->nullable(); //api call rate limit
            $table->string('randomSecret')->unique(); 
            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('tokens');
    }
}
