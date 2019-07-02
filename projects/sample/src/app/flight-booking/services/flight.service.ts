import { Inject, Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { BASE_URL } from '../../app.tokens';
import { Flight } from '../../entities/flight';
import { OAuthService } from '../../../../../lib/src/oauth-service';

@Injectable()
export class FlightService {
  public flights: Array<Flight> = [];

  constructor(
    private oauthService: OAuthService,
    private http: HttpClient,
    @Inject(BASE_URL) private baseUrl: string
  ) {
  }

  find(from: string, to: string): void {
    const url = this.baseUrl + '/api/flight';
    const headers = new HttpHeaders().set('Accept', 'application/json');
    // .set('Authorization', 'Bearer ' + this.oauthService.getAccessToken());

    const params = new HttpParams().set('from', from).set('to', to);

    this.http.get<Flight[]>(url, {headers, params}).subscribe(
      flights => {
        this.flights = flights;
      },
      err => {
        console.warn('status', err.status);
      }
    );
  }
}
